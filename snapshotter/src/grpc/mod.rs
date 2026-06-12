// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! gRPC proxy-plugin server for containerd.
//!
//! Uses the `containerd-snapshots` crate to implement the `Snapshotter` trait
//! and serve it over a Unix domain socket.

use crate::auto_zran::AutoZranManager;
use crate::cache::{CacheGcPolicy, CacheManager, parse_duration};
use crate::config::SnapshotterConfig;
use crate::daemon::DaemonSupervisor;
use crate::metrics::SnapshotterMetrics;
use crate::overlay::{NydusMetaInfo, OverlayEngine, PrepareOutcome};
use crate::recon::Reconciler;
use crate::store::{SnapshotInfo, SnapshotStore};
use crate::sysctl::serve_unix as serve_sysctl_unix;
use anyhow::{Context as _, Result};
use containerd_snapshots::{self as snapshots, Info, Kind, Usage};
use futures::Stream;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Small snapshotter error carrier.
///
/// `tonic::Status` is intentionally boxed so `Result<_, Error>` stays small in
/// async trait futures and list streams while still converting cleanly to the
/// gRPC status required by `containerd-snapshots`.
#[derive(Debug)]
pub struct SnapshotterError(Box<snapshots::tonic::Status>);

impl SnapshotterError {
    fn not_found(message: impl Into<String>) -> Self {
        Self(Box::new(snapshots::tonic::Status::not_found(
            message.into(),
        )))
    }

    fn internal(message: impl Into<String>) -> Self {
        Self(Box::new(snapshots::tonic::Status::internal(message.into())))
    }

    fn already_exists(message: impl Into<String>) -> Self {
        Self(Box::new(snapshots::tonic::Status::already_exists(
            message.into(),
        )))
    }

    fn status_label(&self) -> &'static str {
        match self.0.code() {
            snapshots::tonic::Code::Ok => "ok",
            snapshots::tonic::Code::Cancelled => "cancelled",
            snapshots::tonic::Code::Unknown => "unknown",
            snapshots::tonic::Code::InvalidArgument => "invalid_argument",
            snapshots::tonic::Code::DeadlineExceeded => "deadline_exceeded",
            snapshots::tonic::Code::NotFound => "not_found",
            snapshots::tonic::Code::AlreadyExists => "already_exists",
            snapshots::tonic::Code::PermissionDenied => "permission_denied",
            snapshots::tonic::Code::ResourceExhausted => "resource_exhausted",
            snapshots::tonic::Code::FailedPrecondition => "failed_precondition",
            snapshots::tonic::Code::Aborted => "aborted",
            snapshots::tonic::Code::OutOfRange => "out_of_range",
            snapshots::tonic::Code::Unimplemented => "unimplemented",
            snapshots::tonic::Code::Internal => "internal",
            snapshots::tonic::Code::Unavailable => "unavailable",
            snapshots::tonic::Code::DataLoss => "data_loss",
            snapshots::tonic::Code::Unauthenticated => "unauthenticated",
        }
    }
}

impl From<SnapshotterError> for snapshots::tonic::Status {
    fn from(error: SnapshotterError) -> Self {
        *error.0
    }
}

/// Convert our `SnapshotInfo` to the containerd `Info` type.
fn info_to_snapshots(si: SnapshotInfo) -> Info {
    Info {
        kind: match si.kind.as_str() {
            "kind_active" => Kind::Active,
            "kind_committed" => Kind::Committed,
            "kind_view" => Kind::View,
            _ => Kind::Unknown,
        },
        name: si.key,
        parent: si.parent.unwrap_or_default(),
        labels: si.labels,
        created_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(si.created_at as u64),
        updated_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(si.updated_at as u64),
    }
}

fn snapshot_status_label<T>(result: &Result<T, SnapshotterError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(error) => error.status_label(),
    }
}

/// The main snapshotter implementation.
///
/// Bridges containerd's gRPC proxy-plugin protocol to the overlay engine
/// Parse `lowerdir=…` out of the first overlay mount in `mounts`, returning
/// the *lowest* (closest to the image rootfs) directory in the list. Used by
/// the access tracer to FAN_MARK_MOUNT the image's filesystem rather than
/// the overlay's merged view (which includes the writable upper).
///
/// containerd overlay mounts encode the layer stack as
/// `lowerdir=L0:L1:…:Ln,upperdir=U,workdir=W`, where `L0` is the layer
/// closest to the rootfs read order. For a multi-layer image any of the
/// L0..Ln directories live on the same filesystem (the snapshotter's
/// snapshots root), so marking any one of them with `FAN_MARK_MOUNT`
/// captures opens across the whole stack on that mount.
fn first_lowerdir(mounts: &[snapshots::api::types::Mount]) -> Option<PathBuf> {
    for mount in mounts {
        if mount.r#type != "overlay" {
            continue;
        }
        for opt in &mount.options {
            if let Some(rest) = opt.strip_prefix("lowerdir=")
                && let Some(first) = rest.split(':').next()
                && !first.is_empty()
            {
                return Some(PathBuf::from(first));
            }
        }
    }
    None
}

/// Extract the chainID digest from a snapshot parent string. containerd's
/// proxy-plugin protocol prefixes the snapshot key with the namespace and an
/// incrementing id (e.g. `k8s.io/18004/sha256:ead2…64hex`), so the actual
/// digest lives after the last `/`. Returns `None` when the suffix isn't a
/// `sha256:<64-hex>` digest. The hex-length check (vs just the prefix)
/// guards against a future containerd format change leaking a partial
/// or non-hex suffix through to `ContainerdLookup`, which would then
/// silently miss for every prepare on the node.
fn parent_chain_digest(parent: &str) -> Option<&str> {
    let suffix = parent.rsplit('/').next().unwrap_or(parent);
    let hex = suffix.strip_prefix("sha256:")?;
    (hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())).then_some(suffix)
}

/// and daemon supervisor.
pub struct NydusSnapshotter {
    store: Arc<SnapshotStore>,
    overlay: OverlayEngine,
    supervisor: Arc<DaemonSupervisor>,
    metrics: Arc<SnapshotterMetrics>,
    /// Auto-accel access tracer. Disabled (no-op) when
    /// `auto_zran.capture.enable = false` or fanotify init fails; cheap
    /// (no-op) clone otherwise.
    access_tracer: Arc<crate::access_tracer::AccessTracer>,
    /// Auto-accel sidecar discovery + staging. `Some` when `auto_zran.enable`
    /// is on (with a containerd content-store client behind it); `None`
    /// otherwise — in which case `resolve_auto_accel_mount` is a no-op.
    auto_accel_discovery: Option<crate::auto_accel_sidecar::AutoAccelDiscovery>,
    /// Containerd-side state used by `resolve_auto_accel_mount` to resolve
    /// an image ref to its manifest digest. `None` when auto-accel is off.
    containerd_lookup: Option<Arc<crate::containerd_lookup::ContainerdLookup>>,
    containerd_content_root: Option<PathBuf>,
}

impl NydusSnapshotter {
    /// Ensure the Nydus daemon for `parent`'s rootfs is mounted, then return
    /// its mountpoint and a snapshot of the underlying meta info. Returns
    /// `Ok(None)` when the parent chain does not include a Nydus meta layer.
    async fn resolve_nydus_mount(
        &self,
        parent: &str,
        call_labels: &HashMap<String, String>,
    ) -> Result<Option<(NydusMetaInfo, PathBuf)>, SnapshotterError> {
        let store = self.store.as_ref();
        let meta = self
            .overlay
            .nydus_meta_info(store, parent, call_labels)
            .map_err(|e| SnapshotterError::internal(e.to_string()))?;
        let Some(meta) = meta else {
            return Ok(None);
        };
        let handle = self
            .supervisor
            .ensure_instance(&meta.image_ref, &meta.bootstrap)
            .await
            .map_err(|e| {
                warn!(image_ref = %meta.image_ref, error = %e, "failed to start nydus daemon");
                SnapshotterError::internal(e.to_string())
            })?;
        let mountpoint = handle.mountpoint().to_path_buf();
        Ok(Some((meta, mountpoint)))
    }

    /// Resolve a sidecar-backed auto-accel mount for `image_ref` if one is
    /// present in containerd's content store (locally produced or
    /// spegel-mirrored). Returns the daemon mountpoint to substitute for the
    /// overlay mount, or `Ok(None)` when no sidecar exists or auto-accel is
    /// disabled — the caller falls back to overlay.
    ///
    /// Distinct from `resolve_nydus_mount` (which handles tag-of-image-was-
    /// converted nydus-meta layers) because the auto-accel path uses a
    /// localfs+fanotify daemon over symlinked gzip layers, not a registry
    /// FUSE/RAFS mount.
    async fn resolve_auto_accel_mount(
        &self,
        image_ref: &str,
    ) -> Result<Option<PathBuf>, SnapshotterError> {
        let (Some(discovery), Some(lookup), Some(content_root)) = (
            self.auto_accel_discovery.as_ref(),
            self.containerd_lookup.as_ref(),
            self.containerd_content_root.as_ref(),
        ) else {
            return Ok(None);
        };
        let info = match lookup.manifest_info(image_ref, content_root).await {
            Ok(info) => info,
            Err(e) => {
                debug!(image_ref, error = %e, "auto-accel manifest_info failed; falling back to overlay");
                return Ok(None);
            }
        };
        let staged = match discovery.resolve(&info.manifest_digest).await {
            Ok(Some(s)) => s,
            Ok(None) => return Ok(None),
            Err(e) => {
                warn!(image_ref, error = %e, "auto-accel discovery failed; falling back to overlay");
                return Ok(None);
            }
        };
        // Daemon start failure is NON-FATAL: the sidecar mount is an
        // optimization, never a requirement. Failing the prepare here
        // wedged pods in CreateContainerError loops on hosts where the
        // fanotify daemon couldn't come up; falling back to overlay keeps
        // the pod scheduling while the warn (with the full error chain)
        // tells the operator why acceleration is off.
        let handle = match self
            .supervisor
            .ensure_instance_local(image_ref, &staged.bootstrap, &staged.backend_dir)
            .await
        {
            Ok(handle) => handle,
            Err(e) => {
                warn!(
                    image_ref,
                    error = format!("{e:#}"),
                    "auto-accel fanotify daemon failed to start; falling back to overlay"
                );
                return Ok(None);
            }
        };
        debug!(
            image_ref,
            mountpoint = %handle.mountpoint().display(),
            "auto-accel mount ready"
        );
        Ok(Some(handle.mountpoint().to_path_buf()))
    }

    fn rewrite_mounts_with_daemon(
        &self,
        key: &str,
        daemon_mountpoint: &Path,
        readonly: bool,
    ) -> Vec<snapshots::api::types::Mount> {
        vec![
            self.overlay
                .mount_with_daemon(key, daemon_mountpoint, readonly),
        ]
    }
}

#[snapshots::tonic::async_trait]
impl snapshots::Snapshotter for NydusSnapshotter {
    type Error = SnapshotterError;
    type InfoStream = Pin<Box<dyn Stream<Item = Result<Info, Self::Error>> + Send>>;

    async fn stat(&self, key: String) -> Result<Info, Self::Error> {
        let timer = self.metrics.start_snapshot_operation("stat");
        let result = async {
            debug!(key, "stat snapshot");
            let store = self.store.as_ref();
            store.stat(&key).map(info_to_snapshots).map_err(|e| {
                debug!(key, error = %e, "stat snapshot failed");
                SnapshotterError::not_found(e.to_string())
            })
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    async fn update(
        &self,
        info: Info,
        _fieldpaths: Option<Vec<String>>,
    ) -> Result<Info, Self::Error> {
        let timer = self.metrics.start_snapshot_operation("update");
        let result = async {
            info!(name = %info.name, fieldpaths = ?_fieldpaths, labels = ?info.labels, "update snapshot");
            let store = self.store.as_ref();
            let labels: Vec<(String, String)> = info.labels.into_iter().collect();
            store.update(&info.name, &labels).map_err(|e| {
                warn!(name = %info.name, error = %e, "update snapshot failed");
                SnapshotterError::internal(e.to_string())
            })?;
            // Re-fetch the updated info
            store.stat(&info.name).map(info_to_snapshots).map_err(|e| {
                warn!(name = %info.name, error = %e, "stat updated snapshot failed");
                SnapshotterError::internal(e.to_string())
            })
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    async fn usage(&self, key: String) -> Result<Usage, Self::Error> {
        let timer = self.metrics.start_snapshot_operation("usage");
        let result = async {
            debug!(key, "usage snapshot");
            let store = self.store.as_ref();
            let (size, inodes) = self.overlay.usage(store, &key).map_err(|e| {
                warn!(key, error = %e, "usage snapshot failed");
                SnapshotterError::internal(e.to_string())
            })?;
            Ok(Usage { inodes, size })
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    async fn mounts(&self, key: String) -> Result<Vec<snapshots::api::types::Mount>, Self::Error> {
        let timer = self.metrics.start_snapshot_operation("mounts");
        let result = async {
            debug!(key, "mounts snapshot");
            let store = self.store.as_ref();
            let info = store
                .stat(&key)
                .map_err(|e| SnapshotterError::not_found(e.to_string()))?;
            let readonly = info.kind == "kind_view";
            let parent = info.parent.clone().unwrap_or_default();
            let labels = info.labels.clone();

            if let Some((_, daemon_mnt)) = self.resolve_nydus_mount(&parent, &labels).await? {
                return Ok(self.rewrite_mounts_with_daemon(&key, &daemon_mnt, readonly));
            }

            self.overlay.mounts(store, &key).map_err(|e| {
                warn!(key, error = %e, "mounts snapshot failed");
                SnapshotterError::internal(e.to_string())
            })
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    async fn prepare(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<snapshots::api::types::Mount>, Self::Error> {
        let timer = self.metrics.start_snapshot_operation("prepare");
        let result = async {
            info!(
                %key,
                %parent,
                ?labels,
                "prepare snapshot"
            );
            let store = self.store.as_ref();
            let outcome = self
                .overlay
                .prepare(store, &key, &parent, &labels)
                .map_err(|e| {
                    warn!(key, parent, error = %e, "prepare snapshot failed");
                    SnapshotterError::internal(e.to_string())
                })?;

            match outcome {
                PrepareOutcome::Mounts(mounts) => {
                    if let Some((_, daemon_mnt)) = self.resolve_nydus_mount(&parent, &labels).await? {
                        debug!(key, parent, mountpoint = %daemon_mnt.display(), "prepared nydus rootfs");
                        return Ok(self.rewrite_mounts_with_daemon(&key, &daemon_mnt, false));
                    }
                    // Resolve the image-ref for this prepare. containerd's
                    // CRI plugin (v2.x in k3s 1.36+) does not pass
                    // `cri.image-ref` on the container rootfs prepare —
                    // labels are empty. Fall back to a chainID lookup against
                    // containerd's image store via `ContainerdLookup`, which
                    // walks images once and caches `topmost chainID →
                    // image_ref` for every image containerd knows.
                    //
                    // Unpack prepares (containerd's image-puller extracting
                    // layers, marked by `containerd.io/snapshot.ref`) are
                    // skipped outright: their chain digests belong to a
                    // still-incomplete image that can never be in the cache,
                    // so each one would trigger a full image walk — during a
                    // multi-layer pull that turned into one walk PER LAYER
                    // and minutes of added pull latency.
                    let is_unpack = labels.contains_key("containerd.io/snapshot.ref");
                    let mut image_ref = labels.get(crate::source::labels::CRI_IMAGE_REF).cloned();
                    if image_ref.is_none()
                        && !is_unpack
                        && let Some(chain) = parent_chain_digest(&parent)
                        && let Some(lookup) = self.containerd_lookup.as_ref()
                    {
                        image_ref = match lookup.lookup(chain).await {
                            Ok(opt) => opt,
                            Err(e) => {
                                // Refresh failure (containerd unreachable,
                                // JSON parse error, etc.) is loudly logged
                                // rather than silently collapsed into a miss
                                // — a missing image-ref disables auto-accel
                                // routing AND capture, and we'd otherwise
                                // have no signal that the lookup pipeline
                                // itself is broken.
                                warn!(chain, parent, error = %e, "containerd-lookup refresh failed; auto-accel disabled for this prepare");
                                None
                            }
                        };
                    }

                    // Auto-accel routing: if a sidecar artifact exists for
                    // this image in containerd's content store (locally
                    // produced or spegel-mirrored), substitute a
                    // localfs+fanotify daemon mount for the overlay. The
                    // original gzip layers stay where they are; the daemon
                    // serves them on demand from the merged bootstrap.
                    if let Some(image_ref) = image_ref.as_deref()
                        && let Some(daemon_mnt) = self.resolve_auto_accel_mount(image_ref).await?
                    {
                        debug!(key, parent, mountpoint = %daemon_mnt.display(), "prepared auto-accel rootfs");
                        return Ok(self.rewrite_mounts_with_daemon(&key, &daemon_mnt, false));
                    }
                    // Auto-accel capture: no sidecar yet, so attach the
                    // tracer to the *lowest* lowerdir (the image's
                    // filesystem) and let it record reads during pod
                    // startup. On settle, a conversion job runs and lands
                    // the sidecar that the next pod (or peer node) picks up
                    // via the resolve_auto_accel_mount branch above.
                    if let (Some(image_ref), Some(image_root)) = (image_ref, first_lowerdir(&mounts))
                        && let Err(e) = self.access_tracer.attach(&image_ref, &image_root)
                    {
                        debug!(image = %image_ref, error = %e, "access_tracer attach failed");
                    }
                    debug!(key, parent, mounts = mounts.len(), "prepared snapshot");
                    Ok(mounts)
                }
                PrepareOutcome::AlreadyExists {
                    target,
                    commit_labels,
                } => {
                    info!(
                        %key,
                        %target,
                        "nydus blob layer; committing target and returning AlreadyExists"
                    );
                    if let Err(e) = self.overlay.commit(store, &target, &key, &commit_labels) {
                        let msg = e.to_string();
                        if msg.contains("already exists") {
                            // Re-prepare of an already-committed target. Drop the
                            // active row we just created so it doesn't leak.
                            if let Err(cleanup) = self.overlay.remove(store, &key) {
                                warn!(%key, error = %cleanup, "failed to clean up active snapshot after idempotent re-prepare");
                            }
                        } else {
                            warn!(%key, %target, error = %e, "commit of nydus blob target failed");
                            return Err(SnapshotterError::internal(msg));
                        }
                    }
                    Err(SnapshotterError::already_exists(format!(
                        "target snapshot {target}"
                    )))
                }
            }
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    async fn view(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<snapshots::api::types::Mount>, Self::Error> {
        let timer = self.metrics.start_snapshot_operation("view");
        let result = async {
            debug!(key, parent, "view snapshot");
            let store = self.store.as_ref();
            let mounts = self
                .overlay
                .view(store, &key, &parent, &labels)
                .inspect(|mounts| {
                    debug!(key, parent, mounts = mounts.len(), "created view snapshot")
                })
                .map_err(|e| {
                    warn!(key, parent, error = %e, "view snapshot failed");
                    SnapshotterError::internal(e.to_string())
                })?;

            if let Some((_, daemon_mnt)) = self.resolve_nydus_mount(&parent, &labels).await? {
                return Ok(self.rewrite_mounts_with_daemon(&key, &daemon_mnt, true));
            }
            Ok(mounts)
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    async fn commit(
        &self,
        name: String,
        key: String,
        labels: HashMap<String, String>,
    ) -> Result<(), Self::Error> {
        let timer = self.metrics.start_snapshot_operation("commit");
        let result = async {
            info!(name, key, ?labels, "commit snapshot");
            let store = self.store.as_ref();
            self.overlay
                .commit(store, &name, &key, &labels)
                .inspect(|_| debug!(name, key, "committed snapshot"))
                .map_err(|e| {
                    warn!(name, key, error = %e, "commit snapshot failed");
                    SnapshotterError::internal(e.to_string())
                })
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    async fn remove(&self, key: String) -> Result<(), Self::Error> {
        let timer = self.metrics.start_snapshot_operation("remove");
        let result = async {
            debug!(key, "remove snapshot");
            let store = self.store.as_ref();
            let stat = store.stat(&key).ok();
            let parent = stat.as_ref().and_then(|info| info.parent.clone());
            let labels = stat
                .as_ref()
                .map(|info| info.labels.clone())
                .unwrap_or_default();
            let release_target = if let Some(parent) = parent.as_deref() {
                self.overlay
                    .nydus_meta_info(store, parent, &labels)
                    .ok()
                    .flatten()
                    .map(|meta| meta.image_ref)
            } else {
                None
            };
            self.overlay
                .remove(store, &key)
                .inspect(|_| debug!(key, "removed snapshot"))
                .map_err(|e| {
                    warn!(key, error = %e, "remove snapshot failed");
                    SnapshotterError::internal(e.to_string())
                })?;
            if let Some(image_ref) = release_target
                && let Err(e) = self.supervisor.release(&image_ref).await
            {
                warn!(image_ref, error = %e, "failed to release nydus daemon refcount");
            }
            Ok(())
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    async fn list(
        &self,
        _snapshotter: String,
        _filters: Vec<String>,
    ) -> Result<Self::InfoStream, Self::Error> {
        let timer = self.metrics.start_snapshot_operation("list");
        let result = async {
            let store = self.store.as_ref();
            let snapshots = store
                .list()
                .map_err(|e| SnapshotterError::internal(e.to_string()))?
                .into_iter()
                .map(|info| Ok(info_to_snapshots(info)));
            Ok(Box::pin(futures::stream::iter(snapshots)) as Self::InfoStream)
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }
}

/// Start the gRPC proxy-plugin server on the configured Unix socket.
pub async fn serve(mut config: SnapshotterConfig) -> Result<()> {
    let (probe_results, selected) = crate::probe::probe_and_promote_driver(
        &mut config.snapshotter.fs_drivers,
        config.snapshotter.fs_driver_policy,
    );
    for result in &probe_results {
        info!(
            driver = ?result.driver_type,
            available = result.available,
            reason = %result.reason,
            "driver probe result"
        );
    }
    let Some(selected) = selected else {
        anyhow::bail!("no viable filesystem driver found during snapshotter startup");
    };
    info!(driver = ?selected, "selected filesystem driver");
    let store = open_store_for_config(&config)?;
    serve_with_supervisor(
        config.clone(),
        Arc::new(DaemonSupervisor::new(config)),
        store,
    )
    .await
}

/// Build the snapshot store at the path the config implies. Pulled out of
/// `serve_with_supervisor` so the binary entry point can open the store before
/// the runtime spawns the server task — that way it can `persist_now()` on a
/// SIGTERM path without reaching into the server task to fish out its handle,
/// which matters because the server task may be cancelled by runtime drop
/// before its inner Drops fire.
pub fn open_store_for_config(config: &SnapshotterConfig) -> Result<Arc<SnapshotStore>> {
    std::fs::create_dir_all(&config.snapshotter.root)?;
    let store_path = PathBuf::from(&config.snapshotter.root).join("metadata.fjall");
    Ok(Arc::new(SnapshotStore::open(&store_path)?))
}

/// Start the gRPC server with a caller-provided supervisor so that the binary
/// entry point can install a SIGTERM handler that shuts the same supervisor
/// down on exit. Callers should pass a config whose filesystem driver list has
/// already been normalized with `probe_and_promote_driver` so all runtime
/// components agree on the active driver.
pub async fn serve_with_supervisor(
    config: SnapshotterConfig,
    supervisor: Arc<DaemonSupervisor>,
    store: Arc<SnapshotStore>,
) -> Result<()> {
    let socket_path = PathBuf::from(&config.snapshotter.address);

    let cache_gc_policy = CacheGcPolicy::from_config(&config)?;
    let cache_manager = CacheManager::from_config(&config);
    let metrics = Arc::new(SnapshotterMetrics::new());

    // Auto-accel: build the access tracer and conversion deps. The tracer is
    // built unconditionally but becomes a no-op when
    // `auto_zran.capture.enable = false` so prepare() can call its attach()
    // without a branch. The `AutoZranManager` (conversion worker) only spins
    // up when `auto_zran.enable = true`.
    let profile_store = crate::prefetch_profile::PrefetchProfileStore::from_cache_root(
        &config.snapshotter.cache.work_dir,
    );
    let access_tracer = crate::access_tracer::AccessTracer::start(
        config.snapshotter.auto_zran.capture.clone(),
        profile_store,
        None, // back-filled below once AutoZranManager exists
    );
    let (auto_zran, auto_accel_discovery, containerd_lookup_for_discovery) =
        if config.snapshotter.auto_zran.enable {
            let content_store =
                crate::content_store::ContentStoreClient::new(&config.snapshotter.containerd)
                    .context("connect to containerd content store")?;
            // gRPC-backed lookup: image walks go over Images.List +
            // Content.Read instead of spawning crictl/ctr per image —
            // the CLI walk took ~80 s per refresh on a loaded node and
            // head-of-line-blocked every other snapshotter call.
            let containerd_lookup = Arc::new(crate::containerd_lookup::ContainerdLookup::new(
                content_store.clone(),
            ));
            let deps = crate::auto_zran::ConversionDeps {
                content_store: content_store.clone(),
                containerd: config.snapshotter.containerd.clone(),
                containerd_lookup: containerd_lookup.clone(),
                access_tracer: access_tracer.clone(),
            };
            let auto_zran = AutoZranManager::start(&config.snapshotter.auto_zran, deps);
            // Back-fill the access_tracer's auto_zran link now that the
            // manager exists. AccessTracer was built first because the
            // manager's `ConversionDeps` borrow the tracer; without this
            // back-fill, settled profiles get persisted to disk but never
            // enqueue into the conversion worker.
            if let Some(ref manager) = auto_zran {
                access_tracer.set_auto_zran(manager.clone());
            }
            let discovery = crate::auto_accel_sidecar::AutoAccelDiscovery::new(
                content_store,
                &config.snapshotter.root,
                &config.snapshotter.spegel_mirror,
            );
            (auto_zran, Some(discovery), Some(containerd_lookup))
        } else {
            (None, None, None)
        };

    // The overlay engine shares the gRPC layer's lookup so its sync
    // `nydus_meta_info` fallback reads the cache the async prepare path
    // populates (cache-only — sync code never walks the image store).
    let overlay = OverlayEngine::new(config.clone())
        .with_containerd_lookup(containerd_lookup_for_discovery.clone());

    if config.snapshotter.sysctl.enable {
        let sysctl_path = config.snapshotter.sysctl.address.clone();
        let controller = crate::sysctl::SystemControllerBuilder::new(
            supervisor.clone(),
            store.clone(),
            cache_manager.clone(),
            cache_gc_policy.clone(),
        )
        .with_metrics(metrics.clone())
        .with_auto_zran(auto_zran.clone())
        .with_access_tracer(Some(access_tracer.clone()))
        .build();
        compio::runtime::spawn(async move {
            if let Err(e) = serve_sysctl_unix(sysctl_path, controller).await {
                warn!(error = %e, "system-controller API exited unexpectedly");
            }
        })
        .detach();
    }

    let reconciler = Reconciler::new(
        supervisor.clone(),
        store.clone(),
        parse_duration(&config.snapshotter.cache.gc_period)?,
    )
    .with_cache_gc(cache_manager, cache_gc_policy);
    compio::runtime::spawn(async move {
        if let Err(e) = reconciler.run().await {
            warn!(error = %e, "reconciler exited unexpectedly");
        }
    })
    .detach();

    let snapshotter = NydusSnapshotter {
        store,
        overlay,
        supervisor,
        metrics,
        access_tracer,
        auto_accel_discovery,
        containerd_lookup: containerd_lookup_for_discovery,
        containerd_content_root: if config.snapshotter.auto_zran.enable {
            Some(config.snapshotter.containerd.content_root.clone())
        } else {
            None
        },
    };

    // Remove stale socket if it exists.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    info!(path = %socket_path.display(), "starting containerd proxy-plugin server");

    // Serve the containerd snapshots gRPC service over compio. The service from
    // `containerd-snapshots` is a tonic tower-service; instead of tonic's tokio
    // transport we mount it as an axum router and run it on the compio runtime
    // via cyper-axum's hyper-http2 server (CompioExecutor). No tokio runtime is
    // involved — the whole snapshotter runs thread-per-core on compio/io_uring.
    let listener = compio::net::UnixListener::bind(&socket_path).await?;
    let grpc = snapshots::server(Arc::new(snapshotter));
    let app = tonic::service::Routes::new(grpc).into_axum_router();
    cyper_axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::CacheMetricSnapshot;
    use crate::source::{NYDUS_DATA_LAYER, TARGET_SNAPSHOT_REF};
    use containerd_snapshots::Snapshotter as _;
    use std::path::Path;
    use tempfile::tempdir;

    fn test_snapshotter(root: &Path) -> NydusSnapshotter {
        let mut config = SnapshotterConfig::default();
        config.snapshotter.root = root.to_path_buf();
        let store = SnapshotStore::open(&root.join("metadata.fjall")).unwrap();
        let overlay = OverlayEngine::new(config.clone());
        let supervisor = Arc::new(DaemonSupervisor::new(config));
        NydusSnapshotter {
            store: Arc::new(store),
            overlay,
            supervisor,
            metrics: Arc::new(SnapshotterMetrics::new()),
            access_tracer: crate::access_tracer::AccessTracer::start(
                Default::default(),
                crate::prefetch_profile::PrefetchProfileStore::from_cache_root(root),
                None,
            ),
            auto_accel_discovery: None,
            containerd_lookup: None,
            containerd_content_root: None,
        }
    }

    fn nydus_blob_labels(target: &str) -> HashMap<String, String> {
        HashMap::from([
            (TARGET_SNAPSHOT_REF.to_string(), target.to_string()),
            (NYDUS_DATA_LAYER.to_string(), "true".to_string()),
        ])
    }

    fn status_code(error: SnapshotterError) -> snapshots::tonic::Code {
        let status: snapshots::tonic::Status = error.into();
        status.code()
    }

    #[compio::test]
    async fn prepare_nydus_blob_commits_target_and_returns_already_exists() {
        let dir = tempdir().unwrap();
        let snapshotter = test_snapshotter(dir.path());
        let target = "sha256:target";
        let key = "extract-1 sha256:blob";
        let labels = nydus_blob_labels(target);

        let err = snapshotter
            .prepare(key.to_string(), String::new(), labels)
            .await
            .expect_err("nydus blob prepare should return AlreadyExists");

        assert_eq!(status_code(err), snapshots::tonic::Code::AlreadyExists);

        let info = snapshotter.stat(target.to_string()).await.unwrap();
        assert_eq!(info.kind, Kind::Committed);
        assert_eq!(
            info.labels.get(NYDUS_DATA_LAYER).map(String::as_str),
            Some("true")
        );
        assert!(snapshotter.stat(key.to_string()).await.is_err());
    }

    #[compio::test]
    async fn prepare_nydus_blob_is_idempotent_when_target_already_exists() {
        let dir = tempdir().unwrap();
        let snapshotter = test_snapshotter(dir.path());
        let target = "sha256:target";

        let first = snapshotter
            .prepare(
                "extract-1 sha256:blob".to_string(),
                String::new(),
                nydus_blob_labels(target),
            )
            .await
            .expect_err("first prepare should return AlreadyExists");
        assert_eq!(status_code(first), snapshots::tonic::Code::AlreadyExists);

        let second_key = "extract-2 sha256:blob";
        let second = snapshotter
            .prepare(
                second_key.to_string(),
                String::new(),
                nydus_blob_labels(target),
            )
            .await
            .expect_err("repeat prepare should still return AlreadyExists");
        assert_eq!(status_code(second), snapshots::tonic::Code::AlreadyExists);

        assert_eq!(
            snapshotter.stat(target.to_string()).await.unwrap().kind,
            Kind::Committed
        );
        assert!(snapshotter.stat(second_key.to_string()).await.is_err());

        let metrics = snapshotter
            .metrics
            .render_prometheus(CacheMetricSnapshot::default());
        assert!(metrics.contains(
            "snapshotter_snapshot_operation_total{snapshot_operation=\"prepare\",status=\"already_exists\"}"
        ));
    }

    /// End-to-end check of the gRPC transport: serve the containerd snapshots
    /// service over compio (cyper-axum + hyper http2) and drive it with a *real*
    /// tonic gRPC client. A `Stat` of a missing key must come back as a clean
    /// `NotFound` gRPC status, exercising the whole path that containerd uses —
    /// HTTP/2 connect, gRPC request decode, handler dispatch, gRPC error encode,
    /// HTTP/2 response — without needing a real containerd.
    #[test]
    fn grpc_transport_round_trips_a_real_client_over_compio() {
        use containerd_snapshots::api::snapshots::v1::{
            StatSnapshotRequest, snapshots_client::SnapshotsClient,
        };

        let dir = tempdir().unwrap();
        let server_root = dir.path().to_path_buf();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            compio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let listener = compio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    addr_tx.send(listener.local_addr().unwrap()).unwrap();
                    let snapshotter = test_snapshotter(&server_root);
                    let grpc = snapshots::server(Arc::new(snapshotter));
                    let app = snapshots::tonic::service::Routes::new(grpc).into_axum_router();
                    cyper_axum::serve(listener, app.into_make_service())
                        .await
                        .unwrap();
                });
        });
        let addr = addr_rx.recv().unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
                .unwrap()
                .connect()
                .await
                .expect("tonic client should connect to the compio cyper-axum gRPC server");
            let mut client = SnapshotsClient::new(channel);
            let status = client
                .stat(StatSnapshotRequest {
                    snapshotter: String::new(),
                    key: "does-not-exist".to_string(),
                })
                .await
                .expect_err("stat of a missing snapshot should return a gRPC error");
            assert_eq!(status.code(), snapshots::tonic::Code::NotFound);
        });

        // The detached server thread keeps serving; keep its root alive.
        std::mem::forget(dir);
    }

    /// `parent_chain_digest` is the linchpin of the Gap 1 fallback: it
    /// parses containerd's `<namespace>/<id>/sha256:<64-hex>` proxy-plugin
    /// key into a digest the lookup cache keys on. Loose validation here
    /// would silently miss every prepare on a node when containerd's
    /// format shifts.
    #[test]
    fn parent_chain_digest_accepts_well_formed_64_hex_digest() {
        let parent = "k8s.io/18004/sha256:\
ead2bc6bac86c94fd0bfe3dda6bd9c1dc39bf2bd2446f8048aee82f437584bb5";
        assert_eq!(
            parent_chain_digest(parent),
            Some("sha256:ead2bc6bac86c94fd0bfe3dda6bd9c1dc39bf2bd2446f8048aee82f437584bb5")
        );
    }

    #[test]
    fn parent_chain_digest_rejects_non_hex_suffix() {
        assert_eq!(
            parent_chain_digest("k8s.io/18004/sha256:not-a-hex-digest"),
            None
        );
    }

    #[test]
    fn parent_chain_digest_rejects_wrong_length_hex() {
        // 63 hex chars instead of 64.
        let parent = "k8s.io/18004/sha256:\
ead2bc6bac86c94fd0bfe3dda6bd9c1dc39bf2bd2446f8048aee82f437584bb";
        assert_eq!(parent_chain_digest(parent), None);
    }

    #[test]
    fn parent_chain_digest_rejects_non_sha256_prefix() {
        assert_eq!(parent_chain_digest("k8s.io/18004/md5:abc"), None);
    }

    #[test]
    fn parent_chain_digest_handles_chain_root_snapshot() {
        // Some prepare keys are bare ids (chain root, sandboxes) — no
        // digest suffix at all. Return None so auto-accel cleanly skips
        // this snapshot rather than passing a garbage key to the cache.
        assert_eq!(parent_chain_digest("k8s.io/2/extract-12345-RC1f"), None);
    }
}
