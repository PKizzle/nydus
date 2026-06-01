// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! gRPC proxy-plugin server for containerd.
//!
//! Uses the `containerd-snapshots` crate to implement the `Snapshotter` trait
//! and serve it over a Unix domain socket.

use crate::auto_zran::AutoZranManager;
use crate::cache::{parse_duration, CacheGcPolicy, CacheManager};
use crate::config::SnapshotterConfig;
use crate::daemon::DaemonSupervisor;
use crate::metrics::SnapshotterMetrics;
use crate::overlay::{NydusMetaInfo, OverlayEngine, PrepareOutcome};
use crate::recon::Reconciler;
use crate::store::{SnapshotInfo, SnapshotStore};
use crate::sysctl::{serve_unix as serve_sysctl_unix, SystemController};
use anyhow::Result;
use containerd_snapshots::{self as snapshots, Info, Kind, Usage};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;
use futures::Stream;
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
/// and daemon supervisor.
pub struct NydusSnapshotter {
    store: Arc<SnapshotStore>,
    overlay: OverlayEngine,
    supervisor: Arc<DaemonSupervisor>,
    metrics: Arc<SnapshotterMetrics>,
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

    fn rewrite_mounts_with_daemon(
        &self,
        key: &str,
        daemon_mountpoint: &Path,
        readonly: bool,
    ) -> Vec<snapshots::api::types::Mount> {
        vec![self
            .overlay
            .mount_with_daemon(key, daemon_mountpoint, readonly)]
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
            if let Some(image_ref) = release_target {
                if let Err(e) = self.supervisor.release(&image_ref).await {
                    warn!(image_ref, error = %e, "failed to release nydus daemon refcount");
                }
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
    serve_with_supervisor(config.clone(), Arc::new(DaemonSupervisor::new(config))).await
}

/// Start the gRPC server with a caller-provided supervisor so that the binary
/// entry point can install a SIGTERM handler that shuts the same supervisor
/// down on exit. Callers should pass a config whose filesystem driver list has
/// already been normalized with `probe_and_promote_driver` so all runtime
/// components agree on the active driver.
pub async fn serve_with_supervisor(
    config: SnapshotterConfig,
    supervisor: Arc<DaemonSupervisor>,
) -> Result<()> {
    let socket_path = PathBuf::from(&config.snapshotter.address);
    let store_path = PathBuf::from(&config.snapshotter.root).join("metadata.fjall");

    // Ensure root directory exists
    std::fs::create_dir_all(&config.snapshotter.root)?;

    let store = Arc::new(SnapshotStore::open(&store_path)?);
    let overlay = OverlayEngine::new(config.clone());
    let cache_gc_policy = CacheGcPolicy::from_config(&config)?;
    let cache_manager = CacheManager::from_config(&config);
    let metrics = Arc::new(SnapshotterMetrics::new());
    let auto_zran = AutoZranManager::start(&config.snapshotter.auto_zran);

    if config.snapshotter.sysctl.enable {
        let sysctl_path = config.snapshotter.sysctl.address.clone();
        let controller = SystemController::new_with_metrics_and_auto_zran(
            supervisor.clone(),
            store.clone(),
            cache_manager.clone(),
            cache_gc_policy.clone(),
            metrics.clone(),
            auto_zran.clone(),
        );
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

    #[tokio::test]
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

    #[tokio::test]
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
}
