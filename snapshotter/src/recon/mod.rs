// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Reconciler loop.
//!
//! Periodically scans the snapshot database and daemon instances to detect
//! and repair drift: orphan mounts, dead instances, stale sockets, partial
//! commits. Errors are classified using the `Recoverable` trait to decide
//! whether to retry, recreate, fallback, or abort.

use crate::cache::{CacheGcPolicy, CacheManager};
use crate::daemon::DaemonSupervisor;
use crate::store::SnapshotStore;
use anyhow::{Context, Result, bail};
use compio::time;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Classification of recoverable vs. fatal errors.
pub trait Recoverable: std::fmt::Display {
    /// Classify the error for the reconciler.
    fn classify(&self) -> ErrorClass {
        ErrorClass::Transient
    }
}

/// Error classification for the reconciler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// Retry with exponential backoff.
    Transient,
    /// Recreate the mount on next access.
    RecreatableMount,
    /// Downgrade the filesystem driver (e.g. fanotify → fusedev).
    NeedsFallback,
    /// Fatal error that cannot recover automatically.
    Fatal,
}

/// Errors produced by low-level reconciler probes before they are classified
/// or wrapped by the public `anyhow::Result` API.
#[derive(Debug, thiserror::Error)]
enum ReconcileProbeError {
    #[error("failed to read /proc/mounts")]
    ReadProcMounts(#[source] std::io::Error),
}

/// Dependencies for the auto-accel sidecar GC sweep (see
/// [`Reconciler::with_sidecar_gc`]).
pub struct SidecarGcDeps {
    pub content_store: crate::content_store::ContentStoreClient,
    pub lookup: Arc<crate::containerd_lookup::ContainerdLookup>,
    pub content_root: PathBuf,
}

/// Reconciler that periodically checks and repairs system state.
pub struct Reconciler {
    supervisor: Arc<DaemonSupervisor>,
    store: Arc<SnapshotStore>,
    cache_gc: Option<(CacheManager, CacheGcPolicy)>,
    auto_zran_sweep: Option<(PathBuf, Duration, Arc<crate::auto_zran::AutoZranManager>)>,
    reoptimize_profiles: Option<crate::prefetch_profile::PrefetchProfileStore>,
    sidecar_gc: Option<SidecarGcDeps>,
    interval: Duration,
    /// Cadence for the expensive passes (cache GC, auto-zran sweep, sidecar
    /// GC): they run only when at least this much time has passed since their
    /// last run, while the cheap passes run every `interval` tick.
    slow_interval: Duration,
    last_slow_pass: std::sync::Mutex<Option<std::time::Instant>>,
    /// Per-mount health probe timeout; `None` disables the probe pass.
    mount_probe_timeout: Option<Duration>,
    /// Overlay engine for resolving which daemon a snapshot would release on
    /// `remove()`; `None` disables refcount reconciliation.
    refcount_recon: Option<Arc<crate::overlay::OverlayEngine>>,
    /// Slugs the last mount-health pass found dead, so each one is logged
    /// when it dies and when it recovers rather than on every tick.
    dead_mounts: std::sync::Mutex<HashSet<String>>,
    /// Allocated bytes of each retained stage, with the `updated_at` of the record it was
    /// measured under: a retained stage has no writer, so it is measured once per retention.
    retained_sizes: std::sync::Mutex<HashMap<String, (i64, u64)>>,
}

impl Reconciler {
    /// Create a new reconciler.
    pub fn new(
        supervisor: Arc<DaemonSupervisor>,
        store: Arc<SnapshotStore>,
        interval: Duration,
    ) -> Self {
        Self {
            supervisor,
            store,
            cache_gc: None,
            auto_zran_sweep: None,
            reoptimize_profiles: None,
            sidecar_gc: None,
            slow_interval: interval,
            interval,
            last_slow_pass: std::sync::Mutex::new(None),
            mount_probe_timeout: None,
            refcount_recon: None,
            dead_mounts: std::sync::Mutex::new(HashSet::new()),
            retained_sizes: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Reconcile daemon refcounts against the snapshot store on the slow
    /// cadence, resolving holders with the same logic `remove()` uses.
    pub fn with_refcount_recon(mut self, overlay: Arc<crate::overlay::OverlayEngine>) -> Self {
        self.refcount_recon = Some(overlay);
        self
    }

    /// Put the expensive passes (cache GC, auto-zran sweep, sidecar GC) on
    /// their own, slower cadence than the tick interval.
    pub fn with_slow_interval(mut self, slow_interval: Duration) -> Self {
        self.slow_interval = slow_interval;
        self
    }

    /// Probe live daemon mountpoints for health every tick, bounding each
    /// probe by `timeout`.
    pub fn with_mount_probe(mut self, timeout: Duration) -> Self {
        self.mount_probe_timeout = Some(timeout);
        self
    }

    /// Enable the auto-accel sidecar GC sweep. Deletes sidecar Image records
    /// (`nydus.auto-accel.local/sidecar:<hex>`) whose subject image no longer
    /// exists on the node, so containerd's GC can collect the sidecar blob tree
    /// — and, transitively, release the original gzip layers the sidecar's
    /// `gc.ref.content.*` labels keep alive for its own data path. Without this
    /// sweep, deleting an accelerated image frees no disk, ever.
    pub fn with_sidecar_gc(mut self, deps: SidecarGcDeps) -> Self {
        self.sidecar_gc = Some(deps);
        self
    }

    /// Enable a cache-GC pass as part of each reconciliation tick.
    pub fn with_cache_gc(mut self, manager: CacheManager, policy: CacheGcPolicy) -> Self {
        self.cache_gc = Some((manager, policy));
        self
    }

    /// Enable the auto-zran stale-job-dir sweep as part of each reconciliation
    /// tick. `work_dir` is `AutoZranConfig::work_dir`; `max_age` is how old a job
    /// dir's mtime must be before it's considered abandoned (a successful
    /// conversion removes its own dir -- see `auto_zran::run_conversion` step 6 --
    /// so anything that lingers past `max_age` is debris from a crash). `manager`
    /// is consulted every pass to exclude the currently-running job's directory
    /// regardless of its mtime.
    pub fn with_auto_zran_sweep(
        mut self,
        work_dir: PathBuf,
        max_age: Duration,
        manager: Arc<crate::auto_zran::AutoZranManager>,
    ) -> Self {
        self.auto_zran_sweep = Some((work_dir, max_age, manager));
        self
    }

    /// Enable the slow-cadence re-optimize trigger: persisted prefetch
    /// profiles are re-enqueued to the auto-zran OPTIMIZE stage (guarded by
    /// the manager's failure cache, dedupe, and the worker's already-optimized
    /// early-exit) so an image is not wedged at Base forever when its first
    /// settle-driven optimize was lost. Requires
    /// [`with_auto_zran_sweep`](Self::with_auto_zran_sweep) for the manager.
    pub fn with_reoptimize_profiles(
        mut self,
        store: crate::prefetch_profile::PrefetchProfileStore,
    ) -> Self {
        self.reoptimize_profiles = Some(store);
        self
    }

    /// Run the reconciliation loop indefinitely.
    pub async fn run(&self) -> Result<()> {
        let mut interval = time::interval(self.interval);
        loop {
            interval.tick().await;
            if let Err(e) = self.reconcile().await {
                error!(error = %e, "reconciliation pass failed");
            }
        }
    }

    /// Run a single reconciliation pass on demand and return its result to the
    /// caller (unlike [`Reconciler::run`], which loops and only logs errors).
    /// Wired to the containerd Cleanup RPC so an operator/containerd can force
    /// orphan reclamation synchronously instead of waiting for the next tick.
    ///
    /// May run concurrently with the background loop (both share one
    /// `Arc<Reconciler>`): every reconcile op must remain idempotent and
    /// read-mostly. There is deliberately no pass-wide in-flight guard — a
    /// redundant overlapping pass is cheap and self-correcting. The mount-health
    /// probe is the exception and guards itself: an overlapping probe pass gets
    /// the last report (`DaemonSupervisor::probe_mount_health`).
    pub async fn run_once(&self) -> Result<()> {
        self.reconcile().await
    }

    /// Perform a single reconciliation pass. Cheap passes run every tick; the
    /// expensive ones (cache GC, auto-zran sweep, sidecar GC — image
    /// enumeration and cache-tree walks) only when `slow_interval` has passed
    /// since their last run.
    async fn reconcile(&self) -> Result<()> {
        debug!("starting reconciliation pass");
        // A failing step must not starve the steps after it, so every step
        // runs and the failures are reported together at the end.
        let mut failed = Vec::new();
        let mut note = |step: &'static str, result: Result<()>| {
            if let Err(e) = result {
                warn!(step, error = %format!("{e:#}"), "reconcile step failed");
                failed.push(format!("{step}: {e:#}"));
            }
        };

        // 1. Recover failed daemon instances.
        note("recover daemons", self.supervisor.recover().await.map(drop));

        // 2. Check for orphan overlay mounts under the snapshots root.
        note("orphan mounts", self.check_orphan_mounts().await);

        let run_slow = {
            let mut last = self.last_slow_pass.lock().unwrap();
            let due = last.is_none_or(|at| at.elapsed() >= self.slow_interval);
            if due {
                *last = Some(std::time::Instant::now());
            }
            due
        };

        // 3. Evict retained stages past their limits and sweep stale per-daemon state
        //    directories. On the slow pass this runs before the cache GC, so retained stages
        //    go before any work_dir file.
        note(
            "stale daemon dirs",
            self.check_stale_daemon_dirs(run_slow).await,
        );

        // 4. Probe live daemon mountpoints for consumer-visible health.
        self.check_mount_health().await;

        if run_slow {
            // 5. Account for and optionally garbage-collect blob-cache artifacts.
            note("cache gc", self.check_cache_gc().await);

            // 6. Sweep orphaned auto-zran per-job scratch dirs left by a crash.
            note("auto-zran job dirs", self.check_stale_autozran_dirs().await);

            // 7. Sweep sidecar Image records whose subject image is gone.
            note("orphan sidecars", self.check_orphan_sidecars().await);

            // 7b. Sweep short links whose snapshot directory is gone.
            note("orphan short links", self.check_orphan_short_links().await);

            // 8. Clamp leaked daemon refcounts to the observed holder set.
            self.check_refcounts().await;

            // 9. Re-enqueue the optimize stage for images stuck at Base.
            self.check_stuck_optimizes().await;
        }

        if !failed.is_empty() {
            bail!("reconcile steps failed: {}", failed.join("; "));
        }
        debug!("reconciliation pass complete");
        Ok(())
    }

    /// Re-enqueue the auto-zran OPTIMIZE stage for persisted prefetch
    /// profiles (the wedge-at-Base recovery). Profile listing is filesystem
    /// I/O and enqueueing is synchronous, so the whole pass runs on the
    /// blocking pool.
    async fn check_stuck_optimizes(&self) {
        let (Some((_, _, manager)), Some(store)) =
            (&self.auto_zran_sweep, &self.reoptimize_profiles)
        else {
            return;
        };
        let manager = Arc::clone(manager);
        let store = store.clone();
        let submitted = blocking::unblock(move || manager.retry_stuck_optimizes(&store)).await;
        if submitted > 0 {
            debug!(
                profiles = submitted,
                "recon: re-submitted persisted prefetch profiles to the optimize stage"
            );
        }
    }

    /// Run the mount-health probe pass and log each mount once when it turns
    /// dead and once when it recovers. Purely observational — remediation is
    /// deliberately left to operators/alerts consuming the metrics and
    /// `GET /api/v1/mounts/health`, which report every pass: a mount that
    /// answers reads with EIO (a kernel bug, say) is not fixed by remounting
    /// it, so a recovery loop would only churn.
    async fn check_mount_health(&self) {
        let Some(timeout) = self.mount_probe_timeout else {
            return;
        };
        let report = self.supervisor.probe_mount_health(timeout).await;
        let (newly_dead, recovered) =
            dead_mount_transitions(&mut self.dead_mounts.lock().unwrap(), &report.results);
        for result in recovered {
            info!(
                slug = %result.slug,
                image_ref = %result.image_ref,
                "nydus mount healthy again"
            );
        }
        for result in newly_dead {
            warn!(
                slug = %result.slug,
                image_ref = %result.image_ref,
                mountpoint = %result.mountpoint.display(),
                fstype = result.fstype.as_deref().unwrap_or("none"),
                affected_overlays = result.affected_overlays,
                error = result.error.as_deref().unwrap_or("unknown"),
                "dead nydus mount detected"
            );
        }
    }

    /// Build the observed holder map (image_ref -> snapshot keys that would
    /// release it on `remove()`) and clamp daemon refcounts to it. Aborts
    /// without touching anything if the store cannot be enumerated or any
    /// snapshot's daemon resolution *errors* — a holder we fail to resolve
    /// must never be clamped away. (A snapshot that legitimately resolves to
    /// no daemon — a plain overlay image — is simply not a holder.)
    async fn check_refcounts(&self) {
        let Some(overlay) = &self.refcount_recon else {
            return;
        };
        let overlay = overlay.clone();
        let store = self.store.clone();
        // Sync fjall reads + parent-chain walks — off the reactor.
        let observed = blocking::unblock(move || -> Result<HashMap<String, HashSet<String>>> {
            let mut observed: HashMap<String, HashSet<String>> = HashMap::new();
            for snap in store.list().context("list snapshots for refcount recon")? {
                let stamped = snap
                    .labels
                    .get(crate::source::labels::NYDUS_DAEMON_IMAGE_REF)
                    .cloned();
                let resolved = match stamped {
                    Some(image_ref) => Some(image_ref),
                    None => match snap.parent.as_deref() {
                        Some(parent) => overlay
                            .nydus_meta_info(&store, parent, &snap.labels)
                            .with_context(|| format!("resolve daemon for snapshot {}", snap.key))?
                            .map(|meta| meta.image_ref),
                        None => None,
                    },
                };
                if let Some(image_ref) = resolved {
                    observed.entry(image_ref).or_default().insert(snap.key);
                }
            }
            Ok(observed)
        })
        .await;
        let observed = match observed {
            Ok(observed) => observed,
            Err(e) => {
                warn!(error = %e, "skipping refcount reconciliation; holder resolution incomplete");
                return;
            }
        };
        let report = self.supervisor.reconcile_refcounts(&observed).await;
        if report.clamped > 0 || report.stopped > 0 {
            info!(
                checked = report.checked,
                clamped = report.clamped,
                stopped = report.stopped,
                "refcount reconciliation clamped leaked references"
            );
        }
    }

    /// Delete auto-accel sidecar Image records whose subject image no longer
    /// exists on the node (see [`Reconciler::with_sidecar_gc`]). Best-effort
    /// and conservative: any failure to enumerate or resolve images aborts the
    /// pass without deleting anything, so a transient containerd hiccup can
    /// never sweep a live sidecar.
    async fn check_orphan_sidecars(&self) -> Result<()> {
        let Some(deps) = &self.sidecar_gc else {
            return Ok(());
        };
        const SIDECAR_PREFIX: &str = "nydus.auto-accel.local/sidecar:";

        let images = match deps.content_store.images_list().await {
            Ok(images) => images,
            Err(e) => {
                debug!(error = %e, "recon: images list failed; skipping sidecar sweep");
                return Ok(());
            }
        };
        let sidecars: Vec<_> = images
            .iter()
            .filter(|img| img.name.starts_with(SIDECAR_PREFIX))
            .collect();
        if sidecars.is_empty() {
            return Ok(());
        }

        // Resolve every non-sidecar image to the platform-manifest digest that
        // auto-accel uses as the sidecar subject (`manifest_info` performs the
        // same tag → index → platform-manifest resolution the producer did).
        let mut live_subjects = std::collections::HashSet::new();
        for img in images
            .iter()
            .filter(|i| !i.name.starts_with(SIDECAR_PREFIX))
        {
            match deps
                .lookup
                .manifest_info(&img.name, &deps.content_root)
                .await
            {
                Ok(info) => {
                    live_subjects.insert(info.manifest_digest);
                }
                Err(e) => {
                    // Unresolvable image ⇒ unknown subject ⇒ deleting anything
                    // now could sweep a live sidecar. Try again next tick.
                    debug!(
                        image = %img.name,
                        error = %e,
                        "recon: image unresolvable; aborting sidecar sweep for this pass"
                    );
                    return Ok(());
                }
            }
        }

        let mut removed = 0usize;
        for sidecar in sidecars {
            let subject_hex = &sidecar.name[SIDECAR_PREFIX.len()..];
            let subject = format!("sha256:{subject_hex}");
            if live_subjects.contains(&subject) {
                continue;
            }
            match deps.content_store.images_delete(&sidecar.name).await {
                Ok(()) => {
                    removed += 1;
                    info!(
                        sidecar = %sidecar.name,
                        subject = %subject,
                        "recon: removed orphan auto-accel sidecar record (subject image gone)"
                    );
                }
                Err(e) => warn!(
                    sidecar = %sidecar.name,
                    error = %e,
                    "recon: failed to remove orphan sidecar record"
                ),
            }
        }
        if removed > 0 {
            info!(removed, "recon: orphan sidecar sweep completed");
        }
        Ok(())
    }

    /// Scan `/proc/mounts` for overlay or fuse mounts rooted under the
    /// snapshotter state directory and unmount any that no longer correspond
    /// to a live snapshot or active daemon mountpoint.
    async fn check_orphan_mounts(&self) -> Result<()> {
        let snapshots_root = self
            .supervisor
            .daemons_root()
            .parent()
            .map(Path::to_path_buf);
        let snapshotter_root = match snapshots_root {
            Some(p) => p,
            None => return Ok(()),
        };

        // Build the set of mountpoints we recognise as live: snapshot `fs/`
        // dirs that the store still knows about, plus active daemon mountpoints.
        let mut known: HashSet<PathBuf> = HashSet::new();
        match self.store.list() {
            Ok(snapshots) => {
                let fs_root = snapshotter_root.join("snapshots");
                for snap in snapshots {
                    let dir = fs_root.join(crate::overlay::snapshot_dir_name(&snap.key));
                    known.insert(dir.join("fs"));
                    known.insert(dir.join("work"));
                }
            }
            Err(e) => {
                warn!(error = %e, "recon: failed to list snapshots; skipping orphan-mount scan");
                return Ok(());
            }
        }
        for (_image_ref, mp) in self.supervisor.active_mountpoints().await {
            known.insert(mp);
        }

        let mounts = match read_proc_mounts() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "recon: /proc/mounts unreadable; skipping orphan scan");
                return Ok(());
            }
        };

        let mut orphans = 0usize;
        for entry in mounts {
            let under_root = entry.target.starts_with(&snapshotter_root);
            let interesting = matches!(entry.fs_type.as_str(), "overlay" | "fuse" | "fuse.nydus");
            if !under_root || !interesting {
                continue;
            }
            if known.contains(&entry.target) {
                continue;
            }
            orphans += 1;
            warn!(
                target = %entry.target.display(),
                fs_type = %entry.fs_type,
                "recon: detected orphan mount (not unmounting in v1; logging only)"
            );
        }
        if orphans > 0 {
            info!(orphans, "recon: orphan mount scan completed");
        } else {
            debug!("recon: orphan mount scan clean");
        }
        Ok(())
    }

    /// Sweep `{root}/l/` short links whose snapshot directory is gone.
    ///
    /// `OverlayEngine::remove` unlinks a snapshot's short link best-effort:
    /// aborting a removal over a derived symlink would strand the snapshot
    /// DIRECTORY, whose name is the committed chain id, and `commit` refuses a
    /// destination that already exists -- so the layer could never be pulled
    /// again. The cost of that choice is a link that can outlive its snapshot,
    /// which this reclaims. It also clears the only lasting form of an FNV
    /// short-name collision: a stale link that would otherwise make a
    /// colliding key's mounts fail until an operator intervened.
    async fn check_orphan_short_links(&self) -> Result<()> {
        let Some(snapshotter_root) = self
            .supervisor
            .daemons_root()
            .parent()
            .map(Path::to_path_buf)
        else {
            return Ok(());
        };
        let removed = sweep_orphan_short_links(&snapshotter_root.join("l"));
        if removed > 0 {
            info!(removed, "recon: orphan short-link sweep completed");
        }
        Ok(())
    }

    /// Remove `{root}/daemons/<slug>/` directories that no longer correspond
    /// to a live daemon instance. Avoids removing the mountpoint while it is
    /// in use by checking `/proc/mounts` first. With retention on, the stages
    /// of stopped daemon records are kept within the retention limits instead
    /// (see [`Self::check_retention`]); `slow` is whether this is a slow pass.
    /// When the records cannot be read, nothing is swept: a retained stage
    /// would look like a dir without a record.
    async fn check_stale_daemon_dirs(&self, slow: bool) -> Result<()> {
        let daemons_root = self.supervisor.daemons_root();
        let mut keep = self.supervisor.active_slugs().await;
        let mut result = Ok(());
        if let Some(policy) = self.supervisor.retention_policy() {
            let records = self
                .read_daemon_records(&daemons_root)
                .await
                .context("failed to read the daemon records; not sweeping daemon dirs")?;
            let retained: Vec<_> = records
                .iter()
                .filter(|r| !r.record.live && r.has_stage && !keep.contains(&r.record.slug))
                .map(|r| r.record.clone())
                .collect();
            let stopped_without_dir = records
                .into_iter()
                .filter(|r| !r.record.live && !r.has_dir)
                .map(|r| r.record)
                .collect();
            let kept = match self
                .check_retention(policy, &daemons_root, retained.clone(), slow)
                .await
            {
                Ok(kept) => kept,
                // A failed retention pass must not hand the retained stages to the sweep.
                Err(e) => {
                    result = Err(e);
                    retained
                }
            };
            keep.extend(kept.into_iter().map(|r| r.slug));
            let pruned = self
                .supervisor
                .prune_stopped_records(stopped_without_dir, unix_now())
                .await;
            if pruned > 0 {
                info!(pruned, "recon: pruned stopped daemon records");
            }
        }
        // Without the mount table a dir with a mount under it looks sweepable: sweep nothing.
        let busy = match read_proc_mounts() {
            Ok(mounts) => mounts
                .into_iter()
                .map(|e| e.target)
                .collect::<HashSet<PathBuf>>(),
            Err(e) => {
                return result.and(Err(anyhow::Error::new(e)).context("not sweeping daemon dirs"));
            }
        };

        let removed = sweep_stale_daemon_dirs(&daemons_root, &keep, &busy, self.interval)?;
        if removed > 0 {
            info!(removed, "recon: stale daemon dir sweep completed");
        }
        result
    }

    /// The persisted daemon records, each with whether its daemon dir and its stage dir exist,
    /// read in one go on the blocking pool.
    async fn read_daemon_records(&self, daemons_root: &Path) -> std::io::Result<Vec<RecordDirs>> {
        let supervisor = self.supervisor.clone();
        let root = daemons_root.to_path_buf();
        blocking::unblock(move || {
            Ok(supervisor
                .try_read_persisted_records()?
                .into_iter()
                .map(|record| {
                    let dir = root.join(&record.slug);
                    RecordDirs {
                        has_dir: dir.exists(),
                        has_stage: std::fs::symlink_metadata(dir.join("stage"))
                            .is_ok_and(|m| m.is_dir()),
                        record,
                    }
                })
                .collect())
        })
        .await
    }

    /// Evict the retained stages the retention policy chooses ([`crate::retention::plan`]),
    /// one at a time on the blocking pool, and return the retained stages that remain. The plan
    /// is made again after each eviction; a stage whose eviction fails or is refused stays
    /// counted, but is not chosen again this pass. Costs one `statvfs` per tick; a stage's files
    /// are measured once after it became retained, and every cache file only on the slow pass
    /// with `gc_max_bytes` set (not with `gc_dry_run`). A stage that cannot be measured is
    /// counted at its last known size, or left out of the policy this pass.
    async fn check_retention(
        &self,
        policy: crate::retention::Policy,
        daemons_root: &Path,
        mut retained: Vec<crate::daemon::DaemonStatusRecord>,
        slow: bool,
    ) -> Result<Vec<crate::daemon::DaemonStatusRecord>> {
        let now = unix_now();
        let mut stages = Vec::with_capacity(retained.len());
        for record in &retained {
            let memo = self
                .retained_sizes
                .lock()
                .unwrap()
                .get(&record.slug)
                .copied();
            let stage = daemons_root.join(&record.slug).join("stage");
            let measured = match memo {
                Some((at, _)) if at == record.updated_at => None,
                _ => Some(
                    blocking::unblock(move || crate::cache::allocated_tree_bytes(&stage)).await,
                ),
            };
            if let Some(Ok(bytes)) = &measured {
                self.retained_sizes
                    .lock()
                    .unwrap()
                    .insert(record.slug.clone(), (record.updated_at, *bytes));
            }
            let bytes = retained_size(&record.slug, record.updated_at, memo, measured.as_ref());
            if let Some(bytes) = bytes {
                stages.push(crate::retention::Stage {
                    slug: record.slug.clone(),
                    bytes,
                    stopped_at: record.updated_at,
                    gap: record.start_gap,
                    pinned: false,
                });
            }
        }
        self.retained_sizes
            .lock()
            .unwrap()
            .retain(|slug, _| retained.iter().any(|r| &r.slug == slug));

        let root = daemons_root.to_path_buf();
        let mut fs = blocking::unblock(move || filesystem_of(&root))
            .await
            .with_context(|| format!("failed to statvfs {}", daemons_root.display()))?;
        let mut cache_excess = match (&self.cache_gc, slow) {
            (Some((manager, gc)), true) if gc.max_bytes.is_some() && !gc.dry_run => {
                let manager = manager.clone();
                let total = blocking::unblock(move || manager.scan().map(|u| u.total_bytes))
                    .await
                    .context("failed to scan the cache")?;
                total.saturating_sub(gc.max_bytes.unwrap_or(u64::MAX))
            }
            _ => 0,
        };

        while let Some((slug, reason)) =
            crate::retention::plan(&policy, &stages, fs, cache_excess, now)
                .into_iter()
                .next()
        {
            let pos = stages.iter().position(|s| s.slug == slug).expect("planned");
            let at = retained
                .iter()
                .position(|r| r.slug == slug)
                .expect("measured");
            match self.supervisor.evict_retained(&retained[at]).await {
                Ok(true) => {
                    let bytes = stages.remove(pos).bytes;
                    fs.available = fs.available.saturating_add(bytes);
                    cache_excess = cache_excess.saturating_sub(bytes);
                    self.supervisor.retention_stats().record_eviction(reason);
                    info!(
                        slug,
                        reason = reason.label(),
                        bytes,
                        "recon: evicted a retained stage"
                    );
                    retained.remove(at);
                }
                result => {
                    match result {
                        Ok(_) => debug!(slug, "recon: retained stage changed; not evicting it"),
                        Err(e) => {
                            warn!(slug, error = %format!("{e:#}"), "recon: failed to evict a retained stage")
                        }
                    }
                    stages[pos].pinned = true;
                }
            }
        }

        self.supervisor
            .retention_stats()
            .set_gauges(crate::retention::Gauges {
                retained_stages: retained.len() as u64,
                retained_bytes: stages.iter().map(|s| s.bytes).sum(),
                max_bytes: policy.max_bytes.bytes(fs.total),
                min_free: policy.min_free.bytes(fs.total),
                fs_available: fs.available,
            });
        Ok(retained)
    }

    /// Remove `{auto_zran.work_dir}/<job-key>/` scratch directories that have
    /// been abandoned. A surviving dir is NOT necessarily crash debris: a
    /// successful BASE stage deliberately retains its job dir (and
    /// `artifact.json`) so the optimize stage can reuse the create+merge
    /// output, and only a completed OPTIMIZE stage deletes it
    /// (`auto_zran::cleanup_work_dir`). This sweep is the fallback when settle
    /// never arrives (pod died pre-settle, worker crashed mid-conversion).
    /// Sweeping a retained base dir is safe: a later optimize job finds no
    /// reusable base (`auto_zran::load_reusable_base_artifact` → `None`) and
    /// runs the full pipeline instead. `local_accel::convert` gives every
    /// `nydus-image` invocation a fresh per-layer subdirectory (see
    /// `local_accel::fresh_dir`), so sweeping only whole job dirs never
    /// truncates a live worker's in-progress output.
    ///
    /// Staleness is judged by top-level job-dir mtime (which is bumped whenever a
    /// direct child -- `backend/`, `convert/`, the merged `bootstrap`,
    /// `prefetch.json` -- is created, i.e. at job start and at each pipeline
    /// stage) crossed with the manager's live `work_dir_in_use()`, so a long-running
    /// conversion whose job dir hasn't been touched in a while (e.g. deep inside a
    /// single `nydus-image create` call) is never swept out from under it, and nor
    /// is the dir of a job waiting out a containerd outage, whose retry reuses it.
    async fn check_stale_autozran_dirs(&self) -> Result<()> {
        let Some((work_dir, max_age, manager)) = &self.auto_zran_sweep else {
            return Ok(());
        };
        let removed = sweep_stale_job_dirs(
            work_dir,
            *max_age,
            |name| manager.work_dir_in_use(name),
            std::time::SystemTime::now(),
        )?;
        if removed > 0 {
            info!(removed, "recon: auto-zran stale job dir sweep completed");
        }
        Ok(())
    }

    /// Run one configured cache-GC pass. With the default policy this only
    /// reports usage; eviction starts once `gc_max_age` or `gc_max_bytes` is
    /// configured.
    async fn check_cache_gc(&self) -> Result<()> {
        let Some((manager, policy)) = &self.cache_gc else {
            return Ok(());
        };
        let protected = self.supervisor.protected_cache_slugs().await;
        manager
            .garbage_collect(policy, &protected)
            .with_context(|| format!("cache GC failed for {}", manager.root().display()))?;
        Ok(())
    }
}

/// Remove `l/<hash>` symlinks whose target no longer resolves.
///
/// The link points at `../snapshots/<dir>/fs`, so "the snapshot is gone" is
/// exactly "the target does not exist" -- no reverse lookup of the hashed key
/// is needed, and a link whose snapshot is still live always resolves. Entries
/// that are not symlinks are left alone: nothing here creates one, so it is not
/// this sweep's business to guess what it is.
///
/// Best-effort throughout: an unreadable directory or a failed unlink is logged
/// and skipped rather than propagated, so a filesystem hiccup never aborts a
/// reconciliation pass. Returns the number of links removed.
fn sweep_orphan_short_links(link_dir: &Path) -> usize {
    let entries = match std::fs::read_dir(link_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            warn!(
                link_dir = %link_dir.display(),
                error = %e,
                "recon: failed to read the short-link dir; skipping sweep"
            );
            return 0;
        }
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        // `symlink_metadata` describes the link; `metadata` follows it, so a
        // dangling link is exactly an Err here.
        if !path.is_symlink() {
            continue;
        }
        if std::fs::metadata(&path).is_ok() {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                debug!(link = %path.display(), "recon: removed orphan short link");
                removed += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                link = %path.display(),
                error = %e,
                "recon: failed to remove orphan short link"
            ),
        }
    }
    removed
}

/// Remove immediate subdirectories of `work_dir` whose mtime is at least `max_age`
/// old, skipping any dir `is_active` claims (the running job's, or a job's waiting
/// out a containerd outage) no matter how old it looks. Returns the number of
/// directories removed. Pulled out of
/// `Reconciler::check_stale_autozran_dirs` as a pure(-ish) function of its inputs
/// (plus `now`, so tests don't depend on wall-clock timing) so the sweep logic is
/// unit-testable without constructing a full `Reconciler` / `AutoZranManager`.
///
/// `is_active` is re-evaluated immediately before each `remove_dir_all`, NOT
/// snapshotted once up front. Job keys are deterministic (`job_key(image)`), so a
/// same-image conversion that starts mid-sweep reuses the exact dir we may have
/// already decided is stale by mtime. Re-checking at delete time closes that TOCTOU:
/// `mark_started()` (which flips `active_job_key()`) runs before the worker
/// (re)creates the dir, so the delete-time check either sees the now-live job and
/// skips, or the dir is still pure debris and is safe to remove (the worker will
/// recreate a fresh one via `fresh_dir`).
///
/// The whole sweep is best-effort/non-fatal: an unreadable `work_dir` and per-dir
/// removal failures are logged and skipped rather than propagated, so a transient
/// filesystem hiccup never aborts a reconciliation pass.
fn sweep_stale_job_dirs(
    work_dir: &Path,
    max_age: Duration,
    is_active: impl Fn(&str) -> bool,
    now: std::time::SystemTime,
) -> Result<usize> {
    let entries = match std::fs::read_dir(work_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            warn!(
                work_dir = %work_dir.display(),
                error = %e,
                "recon: failed to read auto-zran work dir; skipping sweep"
            );
            return Ok(0);
        }
    };

    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if is_active(&name) {
            continue;
        }
        let age = match entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|modified| now.duration_since(modified).unwrap_or_default())
        {
            Ok(age) => age,
            Err(_) => continue,
        };
        if age < max_age {
            continue;
        }
        // Re-check liveness right before deleting: a same-image job may have
        // started (and reused this exact dir) since we read it above.
        if is_active(&name) {
            continue;
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {
                removed += 1;
                info!(
                    dir = %path.display(),
                    age_secs = age.as_secs(),
                    "recon: removed stale auto-zran job dir"
                );
            }
            Err(e) => warn!(
                dir = %path.display(),
                error = %e,
                "recon: failed to remove stale auto-zran job dir"
            ),
        }
    }
    Ok(removed)
}

/// `Reconciler::check_stale_daemon_dirs` as a function of its inputs so the
/// sweep decision is unit-testable without a full `Reconciler`/`DaemonSupervisor`.
///
/// Removes `{root}/daemons/<slug>/` directories that belong to no live daemon
/// instance and have nothing mounted beneath them. Two classes of entries are
/// never touched:
/// - the [`DaemonSupervisor::RECORDS_DIRNAME`] directory: it holds the persisted
///   `DaemonStatusRecord` JSONs that failover restore pairs with preserved fds —
///   sweeping it between a reconcile tick and the next persist would make a
///   `kill -9` drop parked FUSE fds and leave live mounts serverless;
/// - non-directory entries (stray files are not daemon state and `remove_dir_all`
///   would fail on them anyway).
///
/// Directories modified less than `min_age` ago are also spared: a daemon start
/// creates `daemons/<slug>/` (mountpoint, stage dir) before its instance is
/// registered, so a sweep in that window would delete a starting daemon's state.
fn sweep_stale_daemon_dirs(
    daemons_root: &Path,
    active_slugs: &HashSet<String>,
    busy_mounts: &HashSet<PathBuf>,
    min_age: Duration,
) -> Result<usize> {
    let entries = match std::fs::read_dir(daemons_root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).context("recon: failed to read daemons root"),
    };

    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if name == crate::daemon::DaemonSupervisor::RECORDS_DIRNAME {
            continue;
        }
        if active_slugs.contains(&name) {
            continue;
        }
        let age = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|modified| modified.elapsed().unwrap_or_default())
            .unwrap_or_default();
        if age < min_age {
            continue;
        }
        // Skip if anything under this dir is still mounted.
        if busy_mounts.iter().any(|m| m.starts_with(&path)) {
            warn!(
                dir = %path.display(),
                "recon: stale daemon dir still has active mount; leaving in place"
            );
            continue;
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {
                removed += 1;
                info!(dir = %path.display(), "recon: removed stale daemon dir");
            }
            Err(e) => warn!(
                dir = %path.display(),
                error = %e,
                "recon: failed to remove stale daemon dir"
            ),
        }
    }
    Ok(removed)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Size and space available to unprivileged users of the filesystem holding `path`.
fn filesystem_of(path: &Path) -> std::io::Result<crate::retention::Filesystem> {
    let stat = nix::sys::statvfs::statvfs(path).map_err(std::io::Error::from)?;
    let frsize = stat.fragment_size() as u64;
    Ok(crate::retention::Filesystem {
        total: (stat.blocks() as u64).saturating_mul(frsize),
        available: (stat.blocks_available() as u64).saturating_mul(frsize),
    })
}

/// The size to plan a retained stage with: the memo `(updated_at, bytes)` while it is current,
/// else the fresh `measured` size; when that failed, the last known size, or `None` to leave the
/// stage out of this pass.
fn retained_size(
    slug: &str,
    updated_at: i64,
    memo: Option<(i64, u64)>,
    measured: Option<&std::io::Result<u64>>,
) -> Option<u64> {
    match (memo, measured) {
        (Some((at, bytes)), _) if at == updated_at => Some(bytes),
        (_, Some(Ok(bytes))) => Some(*bytes),
        (memo, Some(Err(e))) => {
            warn!(slug, error = %e, "recon: failed to measure a retained stage");
            memo.map(|(_, bytes)| bytes)
        }
        (_, None) => None,
    }
}

/// A persisted daemon record and what exists of its daemon dir.
struct RecordDirs {
    record: crate::daemon::DaemonStatusRecord,
    has_dir: bool,
    has_stage: bool,
}

/// One row of `/proc/mounts` that the reconciler cares about.
#[derive(Clone, Debug)]
struct MountEntry {
    target: PathBuf,
    fs_type: String,
}

fn read_proc_mounts() -> std::result::Result<Vec<MountEntry>, ReconcileProbeError> {
    let contents =
        std::fs::read_to_string("/proc/mounts").map_err(ReconcileProbeError::ReadProcMounts)?;
    Ok(parse_mounts(&contents))
}

fn parse_mounts(contents: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let (_dev, target, fs_type) = match (parts.next(), parts.next(), parts.next()) {
            (Some(d), Some(t), Some(f)) => (d, t, f),
            _ => continue,
        };
        out.push(MountEntry {
            target: PathBuf::from(unescape_mount_field(target)),
            fs_type: fs_type.to_string(),
        });
    }
    out
}

/// `/proc/mounts` escapes spaces, tabs and backslashes as octal sequences.
pub(crate) fn unescape_mount_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let a = chars.next();
            let b = chars.next();
            let d = chars.next();
            if let (Some(a), Some(b), Some(d)) = (a, b, d)
                && let Ok(code) = u8::from_str_radix(&format!("{a}{b}{d}"), 8)
            {
                out.push(code as char);
                continue;
            }
            out.push('\\');
            if let Some(a) = a {
                out.push(a);
            }
            if let Some(b) = b {
                out.push(b);
            }
            if let Some(d) = d {
                out.push(d);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Fold one probe pass into `dead` (the slugs found dead last pass) and
/// return the results that just turned dead and those that just recovered.
/// A slug absent from the pass (its daemon stopped) is dropped silently.
fn dead_mount_transitions<'a>(
    dead: &mut HashSet<String>,
    results: &'a [crate::daemon::MountProbeResult],
) -> (
    Vec<&'a crate::daemon::MountProbeResult>,
    Vec<&'a crate::daemon::MountProbeResult>,
) {
    let newly_dead = results
        .iter()
        .filter(|r| !r.healthy && !dead.contains(&r.slug))
        .collect();
    let recovered = results
        .iter()
        .filter(|r| r.healthy && dead.contains(&r.slug))
        .collect();
    *dead = results
        .iter()
        .filter(|r| !r.healthy)
        .map(|r| r.slug.clone())
        .collect();
    (newly_dead, recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_mount_is_reported_once_per_transition() {
        let probe = |slug: &str, healthy: bool| crate::daemon::MountProbeResult {
            slug: slug.to_string(),
            image_ref: format!("img-{slug}"),
            mountpoint: PathBuf::from("/mnt"),
            fstype: Some("erofs".to_string()),
            healthy,
            error: (!healthy).then(|| "Input/output error".to_string()),
            latency_ms: 0,
            affected_overlays: 0,
            probed_at: 0,
        };
        let slugs = |v: Vec<&crate::daemon::MountProbeResult>| {
            v.iter().map(|r| r.slug.clone()).collect::<Vec<_>>()
        };
        let mut dead = HashSet::new();

        let pass = [probe("a", false), probe("b", true)];
        let (died, healed) = dead_mount_transitions(&mut dead, &pass);
        assert_eq!(
            (slugs(died), slugs(healed)),
            (vec!["a".to_string()], vec![])
        );

        // Still dead on the following passes: nothing new to report.
        for _ in 0..3 {
            let (died, healed) = dead_mount_transitions(&mut dead, &pass);
            assert!(died.is_empty() && healed.is_empty());
        }

        let pass = [probe("a", true), probe("b", false)];
        let (died, healed) = dead_mount_transitions(&mut dead, &pass);
        assert_eq!(
            (slugs(died), slugs(healed)),
            (vec!["b".to_string()], vec!["a".to_string()])
        );

        // "b" stopped while dead: forgotten, so a later daemon reusing the slug reports again.
        let (died, healed) = dead_mount_transitions(&mut dead, &[]);
        assert!(died.is_empty() && healed.is_empty() && dead.is_empty());
    }

    #[test]
    fn parse_mounts_extracts_target_and_fs_type() {
        let text = "\
overlay /var/lib/containerd-nydus/snapshots/foo/fs overlay rw,lowerdir=...,upperdir=... 0 0
fuse.nydus /var/lib/containerd-nydus/daemons/abc/mnt fuse.nydus rw,user_id=0 0 0
proc /proc proc rw,nosuid 0 0
";
        let parsed = parse_mounts(text);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].fs_type, "overlay");
        assert_eq!(
            parsed[0].target,
            PathBuf::from("/var/lib/containerd-nydus/snapshots/foo/fs")
        );
        assert_eq!(parsed[1].fs_type, "fuse.nydus");
    }

    #[test]
    fn parse_mounts_unescapes_octal_spaces() {
        let text = "tmp /mnt/has\\040space tmpfs rw 0 0\n";
        let parsed = parse_mounts(text);
        assert_eq!(parsed[0].target, PathBuf::from("/mnt/has space"));
    }

    #[test]
    fn parse_mounts_ignores_malformed_lines() {
        let parsed = parse_mounts("garbage\n\n");
        assert!(parsed.is_empty());
    }

    /// One failing step must not skip the rest of the pass.
    #[compio::test]
    async fn a_failing_step_does_not_skip_the_later_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = crate::config::SnapshotterConfig::default();
        config.snapshotter.root = tmp.path().to_path_buf();
        // The stale-daemon-dir sweep fails: its root is not a directory.
        std::fs::write(tmp.path().join("daemons"), b"").unwrap();
        // The short-link sweep, which runs later, has a dangling link to remove.
        let link = tmp.path().join("l/0123456789abcdef");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("gone"), &link).unwrap();
        let reconciler = Reconciler::new(
            Arc::new(DaemonSupervisor::new(config)),
            Arc::new(SnapshotStore::open(&tmp.path().join("metadata.fjall")).unwrap()),
            Duration::from_secs(3600),
        );

        let err = reconciler.run_once().await.unwrap_err();
        assert!(format!("{err:#}").contains("stale daemon dirs"), "{err:#}");
        assert!(!link.is_symlink(), "the short-link sweep must still run");
    }

    fn touch_dir_with_age(root: &Path, name: &str, age: Duration) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let stale_time = std::time::SystemTime::now() - age;
        // `File::open` on a directory (read-only) + `set_modified` is portable on
        // Unix without pulling in a `filetime` dependency just for this test.
        let f = std::fs::File::open(&dir).unwrap();
        f.set_modified(stale_time).unwrap();
        dir
    }

    #[test]
    fn sweep_stale_daemon_dirs_never_removes_the_records_dir() {
        // Regression: the persisted DaemonStatusRecord directory is not a slug
        // and has no mounts, so the pre-fix sweep deleted it on every pass —
        // breaking failover restore after a kill -9.
        let tmp = tempfile::tempdir().unwrap();
        let records = tmp
            .path()
            .join(crate::daemon::DaemonSupervisor::RECORDS_DIRNAME);
        std::fs::create_dir_all(&records).unwrap();
        std::fs::write(records.join("abc.json"), b"{}").unwrap();
        let stale = tmp.path().join("deadbeef-old-image");
        std::fs::create_dir_all(&stale).unwrap();

        let removed =
            sweep_stale_daemon_dirs(tmp.path(), &HashSet::new(), &HashSet::new(), Duration::ZERO)
                .unwrap();

        assert_eq!(removed, 1);
        assert!(
            records.join("abc.json").exists(),
            "records dir must survive"
        );
        assert!(!stale.exists(), "stale slug dir must still be swept");
    }

    #[test]
    fn sweep_stale_daemon_dirs_spares_dirs_younger_than_min_age() {
        // `start_instance` creates `daemons/<slug>/` before the instance is
        // registered; a sweep in that window must not delete it.
        let tmp = tempfile::tempdir().unwrap();
        let starting = touch_dir_with_age(tmp.path(), "cccc-starting", Duration::from_secs(5));
        let stale = touch_dir_with_age(tmp.path(), "dddd-stale", Duration::from_secs(7200));

        let removed = sweep_stale_daemon_dirs(
            tmp.path(),
            &HashSet::new(),
            &HashSet::new(),
            Duration::from_secs(60),
        )
        .unwrap();

        assert_eq!(removed, 1);
        assert!(
            starting.exists(),
            "a daemon dir still starting must survive"
        );
        assert!(!stale.exists());
    }

    #[test]
    fn sweep_stale_daemon_dirs_spares_active_and_mounted_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let active_dir = tmp.path().join("aaaa-live");
        let mounted_dir = tmp.path().join("bbbb-mounted");
        std::fs::create_dir_all(&active_dir).unwrap();
        std::fs::create_dir_all(mounted_dir.join("mnt")).unwrap();
        std::fs::write(tmp.path().join("stray-file"), b"x").unwrap();

        let active: HashSet<String> = ["aaaa-live".to_string()].into();
        let busy: HashSet<PathBuf> = [mounted_dir.join("mnt")].into();

        let removed = sweep_stale_daemon_dirs(tmp.path(), &active, &busy, Duration::ZERO).unwrap();

        assert_eq!(removed, 0);
        assert!(active_dir.exists());
        assert!(mounted_dir.exists());
        assert!(tmp.path().join("stray-file").exists());
    }

    #[test]
    fn sweep_stale_job_dirs_removes_only_dirs_older_than_max_age() {
        let tmp = tempfile::tempdir().unwrap();
        let old = touch_dir_with_age(tmp.path(), "old-crash", Duration::from_secs(7200));
        let fresh = touch_dir_with_age(tmp.path(), "fresh-job", Duration::from_secs(60));

        let removed = sweep_stale_job_dirs(
            tmp.path(),
            Duration::from_secs(3600),
            |_| false,
            std::time::SystemTime::now(),
        )
        .unwrap();

        assert_eq!(removed, 1);
        assert!(!old.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn sweep_stale_job_dirs_never_removes_the_active_job_regardless_of_age() {
        let tmp = tempfile::tempdir().unwrap();
        let active = touch_dir_with_age(tmp.path(), "running-job", Duration::from_secs(999_999));

        let removed = sweep_stale_job_dirs(
            tmp.path(),
            Duration::from_secs(3600),
            |n| n == "running-job",
            std::time::SystemTime::now(),
        )
        .unwrap();

        assert_eq!(removed, 0);
        assert!(active.exists());
    }

    #[test]
    fn sweep_stale_job_dirs_rechecks_liveness_at_delete_time() {
        // Simulate a same-image conversion that starts mid-sweep: `is_active`
        // returns false on the first (pre-mtime-filter) call but true on the
        // delete-time re-check. The stale-by-mtime dir must be spared.
        let tmp = tempfile::tempdir().unwrap();
        let dir = touch_dir_with_age(tmp.path(), "raced-job", Duration::from_secs(7200));
        let calls = std::cell::Cell::new(0u32);

        let removed = sweep_stale_job_dirs(
            tmp.path(),
            Duration::from_secs(3600),
            |name| {
                let n = calls.get();
                calls.set(n + 1);
                // First call (initial skip check): not yet active.
                // Second call (delete-time re-check): job just started.
                n >= 1 && name == "raced-job"
            },
            std::time::SystemTime::now(),
        )
        .unwrap();

        assert_eq!(removed, 0, "delete-time re-check must spare a now-live job");
        assert!(dir.exists());
        assert!(
            calls.get() >= 2,
            "liveness must be checked again before delete"
        );
    }

    #[test]
    fn sweep_stale_job_dirs_tolerates_a_missing_work_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let removed = sweep_stale_job_dirs(
            &missing,
            Duration::from_secs(3600),
            |_| false,
            std::time::SystemTime::now(),
        )
        .unwrap();
        assert_eq!(removed, 0);
    }

    /// A short link outlives its snapshot when `remove()` could not unlink it
    /// (it deliberately does not fail the removal over one). The sweep is what
    /// reclaims it -- and a link whose snapshot is still there must survive.
    #[test]
    fn orphan_short_links_are_swept_and_live_ones_kept() {
        let root = tempfile::tempdir().unwrap();
        let link_dir = root.path().join("l");
        let snapshots = root.path().join("snapshots");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::fs::create_dir_all(snapshots.join("live-snapshot/fs")).unwrap();

        // Points at a snapshot that still exists.
        std::os::unix::fs::symlink(
            Path::new("..")
                .join("snapshots")
                .join("live-snapshot")
                .join("fs"),
            link_dir.join("aaaaaaaaaaaaaaaa"),
        )
        .unwrap();
        // Points at a snapshot that is gone.
        std::os::unix::fs::symlink(
            Path::new("..")
                .join("snapshots")
                .join("removed-snapshot")
                .join("fs"),
            link_dir.join("bbbbbbbbbbbbbbbb"),
        )
        .unwrap();
        // Not a symlink: not this sweep's business.
        std::fs::write(link_dir.join("cccccccccccccccc"), b"stray").unwrap();

        assert_eq!(sweep_orphan_short_links(&link_dir), 1);
        assert!(link_dir.join("aaaaaaaaaaaaaaaa").is_symlink());
        assert!(!link_dir.join("bbbbbbbbbbbbbbbb").exists());
        assert!(link_dir.join("cccccccccccccccc").exists());

        // Idempotent, and a missing dir is not an error.
        assert_eq!(sweep_orphan_short_links(&link_dir), 0);
        assert_eq!(sweep_orphan_short_links(&root.path().join("nope")), 0);
    }

    /// Writes the stopped daemon record of image `name` with stop time `stopped_at` and returns
    /// its daemon dir, holding a stage aged two hours.
    fn retained_stage(root: &Path, name: &str, stopped_at: i64) -> PathBuf {
        let image_ref = format!("registry.example/{name}:1");
        let slug = &crate::daemon::slug_for(&image_ref);
        let records = root.join("daemons/records");
        std::fs::create_dir_all(&records).unwrap();
        let record = serde_json::json!({
            "image_ref": image_ref,
            "slug": slug,
            "mountpoint": root.join("daemons").join(slug).join("mnt"),
            "bootstrap": "/nonexistent/bootstrap",
            "refcount": 0,
            "state": "STOPPED",
            "live": false,
            "updated_at": stopped_at,
        });
        std::fs::write(records.join(format!("{slug}.json")), record.to_string()).unwrap();
        let dir = root.join("daemons").join(slug);
        std::fs::create_dir_all(dir.join("stage")).unwrap();
        std::fs::create_dir_all(dir.join("mnt")).unwrap();
        std::fs::write(dir.join("stage/bootstrap"), vec![1u8; 8192]).unwrap();
        touch_dir_with_age(&root.join("daemons"), slug, Duration::from_secs(7200))
    }

    /// With retention on, a reconcile pass keeps the stage of a released image that is within
    /// its limits, and still sweeps a daemon dir without a record.
    #[compio::test]
    async fn a_reconcile_pass_keeps_a_retained_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config: crate::config::SnapshotterConfig =
            toml::from_str("[snapshotter.cache]\nretention = true\nretention_min_free = \"0%\"\n")
                .unwrap();
        config.snapshotter.root = tmp.path().to_path_buf();
        let now = unix_now();
        let retained = retained_stage(tmp.path(), "retained", now - 60);
        let orphan = touch_dir_with_age(
            &tmp.path().join("daemons"),
            "bbbb-orphan",
            Duration::from_secs(7200),
        );
        let reconciler = Reconciler::new(
            Arc::new(DaemonSupervisor::new(config)),
            Arc::new(SnapshotStore::open(&tmp.path().join("metadata.fjall")).unwrap()),
            Duration::from_secs(3600),
        );

        let _ = reconciler.run_once().await;
        assert!(
            retained.join("stage/bootstrap").exists(),
            "the retained stage was swept"
        );
        assert!(
            !orphan.exists(),
            "a dir without a record is swept as before"
        );
    }

    /// With `gc_dry_run`, `gc_max_bytes` evicts no retained stage either.
    #[compio::test]
    async fn gc_dry_run_evicts_no_retained_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config: crate::config::SnapshotterConfig = toml::from_str(
            "[snapshotter.cache]\nretention = true\nretention_min_free = \"0%\"\n\
             gc_max_bytes = 0\ngc_dry_run = true\n",
        )
        .unwrap();
        config.snapshotter.root = tmp.path().to_path_buf();
        config.snapshotter.cache.work_dir = tmp.path().join("cache");
        let stage = retained_stage(tmp.path(), "recent", unix_now() - 60);
        let manager = CacheManager::from_config(&config);
        let policy = CacheGcPolicy::from_config(&config).unwrap();
        let reconciler = Reconciler::new(
            Arc::new(DaemonSupervisor::new(config)),
            Arc::new(SnapshotStore::open(&tmp.path().join("metadata.fjall")).unwrap()),
            Duration::from_secs(3600),
        )
        .with_cache_gc(manager, policy);

        let _ = reconciler.run_once().await;
        assert!(stage.join("stage/bootstrap").exists());
    }

    /// A stage that cannot be measured keeps its last known size, or sits this pass out.
    #[test]
    fn an_unmeasurable_stage_keeps_its_last_size() {
        let failed = Err(std::io::Error::from_raw_os_error(libc::EIO));
        assert_eq!(retained_size("s", 5, Some((5, 10)), None), Some(10));
        assert_eq!(
            retained_size("s", 6, Some((5, 10)), Some(&Ok(20))),
            Some(20)
        );
        assert_eq!(
            retained_size("s", 6, Some((5, 10)), Some(&failed)),
            Some(10)
        );
        assert_eq!(retained_size("s", 6, None, Some(&failed)), None);
    }

    /// When the records cannot be read, the pass fails and sweeps nothing: a retained stage would
    /// look like a dir without a record.
    #[compio::test]
    async fn unreadable_records_sweep_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config: crate::config::SnapshotterConfig =
            toml::from_str("[snapshotter.cache]\nretention = true\n").unwrap();
        config.snapshotter.root = tmp.path().to_path_buf();
        let stage = retained_stage(tmp.path(), "retained", unix_now() - 60);
        // Not a directory: reading it fails with ENOTDIR, whoever runs the test.
        let records = tmp.path().join("daemons/records");
        std::fs::remove_dir_all(&records).unwrap();
        std::fs::write(&records, b"").unwrap();
        let reconciler = Reconciler::new(
            Arc::new(DaemonSupervisor::new(config)),
            Arc::new(SnapshotStore::open(&tmp.path().join("metadata.fjall")).unwrap()),
            Duration::from_secs(3600),
        );

        let err = reconciler.run_once().await.unwrap_err();
        assert!(format!("{err:#}").contains("daemon records"), "{err:#}");
        assert!(stage.join("stage/bootstrap").exists());
    }

    /// A retained stage idle past its limit is evicted, its record kept. On the slow pass with
    /// `gc_max_bytes` set, retained stages go before any `work_dir` file.
    #[compio::test]
    async fn retention_evicts_idle_stages_before_work_dir_files() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        std::fs::create_dir_all(cache.join("img")).unwrap();
        std::fs::write(cache.join("img/abc.blob.data"), vec![1u8; 4096]).unwrap();
        let mut config: crate::config::SnapshotterConfig = toml::from_str(
            "[snapshotter.cache]\nretention = true\nretention_idle_limit = \"1h\"\n\
             retention_min_free = \"0%\"\n",
        )
        .unwrap();
        config.snapshotter.root = tmp.path().to_path_buf();
        config.snapshotter.cache.work_dir = cache.clone();
        let now = unix_now();
        let idle = retained_stage(tmp.path(), "idle", now - 7200);
        let recent = retained_stage(tmp.path(), "recent", now - 60);
        let manager = CacheManager::from_config(&config);
        let work_dir_bytes = crate::cache::allocated_tree_bytes(&cache).unwrap();
        let recent_bytes = crate::cache::allocated_tree_bytes(&recent.join("stage")).unwrap();
        // Room for the work_dir file, not for the recent stage as well.
        config.snapshotter.cache.gc_max_bytes = Some(work_dir_bytes + recent_bytes / 2);
        let policy = CacheGcPolicy::from_config(&config).unwrap();
        let supervisor = Arc::new(DaemonSupervisor::new(config));
        let reconciler = Reconciler::new(
            supervisor.clone(),
            Arc::new(SnapshotStore::open(&tmp.path().join("metadata.fjall")).unwrap()),
            Duration::from_secs(3600),
        )
        .with_cache_gc(manager, policy);

        let _ = reconciler.run_once().await;
        assert!(!idle.exists(), "the idle stage was kept");
        assert!(!recent.exists(), "the stage went after a work_dir file");
        assert!(cache.join("img/abc.blob.data").exists());
        assert_eq!(supervisor.read_persisted_records().len(), 2);
        let stats = supervisor.retention_stats();
        assert_eq!(stats.evictions(crate::retention::Reason::Idle), 1);
        assert_eq!(stats.evictions(crate::retention::Reason::GcMaxBytes), 1);
        let gauges = stats.gauges().unwrap();
        assert_eq!((gauges.retained_stages, gauges.retained_bytes), (0, 0));
    }
}
