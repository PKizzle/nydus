// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! System-controller backend operations.
//!
//! Endpoint-compatible with the Go snapshotter's system HTTP API. Transport is
//! kept separate from the control plane so the Unix-socket REST server, tests,
//! or a future gRPC admin service can all call the same operations.

use crate::access_tracer::AccessTracer;
use crate::auto_zran::AutoZranManager;
use crate::cache::{CacheArtifactKind, CacheGcPolicy, CacheGcReport, CacheManager, CacheUsage};
use crate::daemon::auth::{RuntimeAuthRequest, runtime_auth_records, set_runtime_auth};
use crate::daemon::{
    DaemonStatusRecord, DaemonSupervisor, DaemonUpgradeOptions, DaemonUpgradeReport,
};
use crate::metrics::{CacheMetricSnapshot, SnapshotterMetrics};
use crate::prefetch_profile::{
    PrefetchProfile, PrefetchProfileStore, normalize_prefetch_files, runtime_prefetch_records,
    set_runtime_prefetch,
};
use crate::store::{SnapshotInfo, SnapshotStore};
use anyhow::{Context, Result};
use compio::net::UnixListener;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const MAX_BODY_BYTES: usize = 1024 * 1024;

/// In-process system controller.
#[derive(Clone)]
pub struct SystemController {
    supervisor: Arc<DaemonSupervisor>,
    store: Arc<SnapshotStore>,
    cache: CacheManager,
    cache_policy: CacheGcPolicy,
    profile_store: PrefetchProfileStore,
    snapshotter_metrics: Arc<SnapshotterMetrics>,
    auto_zran: Option<Arc<AutoZranManager>>,
    access_tracer: Option<Arc<AccessTracer>>,
    metrics: Arc<ControllerMetrics>,
    /// Path of the containerd proxy-plugin gRPC socket, probed by `/readyz`.
    /// `None` (tests, unusual embeddings) makes `/readyz` report not-ready.
    grpc_socket: Option<PathBuf>,
    /// Timeout for on-demand mount probes (`POST /api/v1/mounts/health`).
    mount_probe_timeout: Duration,
}

#[derive(Default)]
struct ControllerMetrics {
    daemon_spawn_runs_total: AtomicU64,
    daemon_spawn_failures_total: AtomicU64,
    daemon_upgrade_runs_total: AtomicU64,
    daemon_upgrade_failures_total: AtomicU64,
    cache_gc_runs_total: AtomicU64,
    cache_gc_removed_files_total: AtomicU64,
    cache_gc_removed_bytes_total: AtomicU64,
    cache_gc_failures_total: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
struct ControllerMetricsSnapshot {
    daemon_spawn_runs_total: u64,
    daemon_spawn_failures_total: u64,
    daemon_upgrade_runs_total: u64,
    daemon_upgrade_failures_total: u64,
    cache_gc_runs_total: u64,
    cache_gc_removed_files_total: u64,
    cache_gc_removed_bytes_total: u64,
    cache_gc_failures_total: u64,
}

impl ControllerMetrics {
    fn record_daemon_spawn(&self, failed: bool) {
        self.daemon_spawn_runs_total.fetch_add(1, Ordering::Relaxed);
        if failed {
            self.daemon_spawn_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_daemon_upgrade(&self, report: &DaemonUpgradeReport) {
        self.daemon_upgrade_runs_total
            .fetch_add(1, Ordering::Relaxed);
        self.daemon_upgrade_failures_total
            .fetch_add(usize_to_u64(report.failed), Ordering::Relaxed);
    }

    fn record_daemon_upgrade_failure(&self) {
        self.daemon_upgrade_runs_total
            .fetch_add(1, Ordering::Relaxed);
        self.daemon_upgrade_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_cache_gc(&self, report: &CacheGcReport, dry_run: bool) {
        self.cache_gc_runs_total.fetch_add(1, Ordering::Relaxed);
        // A dry run reports what *would* be removed but deletes nothing, so it
        // must not inflate the "removed" counters — those feed
        // `snapshotter_cache_blobs_deleted_total`, which alerting reads as
        // actual reclaimed space.
        if !dry_run {
            self.cache_gc_removed_files_total
                .fetch_add(usize_to_u64(report.removed_files), Ordering::Relaxed);
            self.cache_gc_removed_bytes_total
                .fetch_add(report.removed_bytes, Ordering::Relaxed);
        }
        self.cache_gc_failures_total
            .fetch_add(usize_to_u64(report.failures.len()), Ordering::Relaxed);
    }

    fn snapshot(&self) -> ControllerMetricsSnapshot {
        ControllerMetricsSnapshot {
            daemon_spawn_runs_total: self.daemon_spawn_runs_total.load(Ordering::Relaxed),
            daemon_spawn_failures_total: self.daemon_spawn_failures_total.load(Ordering::Relaxed),
            daemon_upgrade_runs_total: self.daemon_upgrade_runs_total.load(Ordering::Relaxed),
            daemon_upgrade_failures_total: self
                .daemon_upgrade_failures_total
                .load(Ordering::Relaxed),
            cache_gc_runs_total: self.cache_gc_runs_total.load(Ordering::Relaxed),
            cache_gc_removed_files_total: self.cache_gc_removed_files_total.load(Ordering::Relaxed),
            cache_gc_removed_bytes_total: self.cache_gc_removed_bytes_total.load(Ordering::Relaxed),
            cache_gc_failures_total: self.cache_gc_failures_total.load(Ordering::Relaxed),
        }
    }
}

/// Builder for [`SystemController`]. Required dependencies go through
/// [`new`](Self::new); optional ones (metrics, auto-zran, access tracer)
/// through the `with_*` methods; `build()` constructs the controller.
pub struct SystemControllerBuilder {
    supervisor: Arc<DaemonSupervisor>,
    store: Arc<SnapshotStore>,
    cache: CacheManager,
    cache_policy: CacheGcPolicy,
    snapshotter_metrics: Option<Arc<SnapshotterMetrics>>,
    auto_zran: Option<Arc<AutoZranManager>>,
    access_tracer: Option<Arc<AccessTracer>>,
    grpc_socket: Option<PathBuf>,
    mount_probe_timeout: Duration,
}

impl SystemControllerBuilder {
    pub fn new(
        supervisor: Arc<DaemonSupervisor>,
        store: Arc<SnapshotStore>,
        cache: CacheManager,
        cache_policy: CacheGcPolicy,
    ) -> Self {
        Self {
            supervisor,
            store,
            cache,
            cache_policy,
            snapshotter_metrics: None,
            auto_zran: None,
            access_tracer: None,
            grpc_socket: None,
            mount_probe_timeout: Duration::from_secs(2),
        }
    }

    /// Timeout for on-demand mount probes (`POST /api/v1/mounts/health`).
    pub fn with_mount_probe_timeout(mut self, timeout: Duration) -> Self {
        self.mount_probe_timeout = timeout;
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<SnapshotterMetrics>) -> Self {
        self.snapshotter_metrics = Some(metrics);
        self
    }

    pub fn with_auto_zran(mut self, auto_zran: Option<Arc<AutoZranManager>>) -> Self {
        self.auto_zran = auto_zran;
        self
    }

    pub fn with_access_tracer(mut self, tracer: Option<Arc<AccessTracer>>) -> Self {
        self.access_tracer = tracer;
        self
    }

    /// Path of the containerd proxy-plugin gRPC socket. `/readyz` reports
    /// ready once this socket accepts connections — the gRPC listener binds
    /// *after* the sysctl server starts, so readiness correctly lags
    /// liveness during startup.
    pub fn with_grpc_socket(mut self, socket: PathBuf) -> Self {
        self.grpc_socket = Some(socket);
        self
    }

    pub fn build(self) -> SystemController {
        let profile_store = PrefetchProfileStore::from_cache_root(self.cache.root());
        if let Err(e) = profile_store.restore_runtime() {
            warn!(error = %e, "failed to restore persisted prefetch profiles");
        }
        SystemController {
            supervisor: self.supervisor,
            store: self.store,
            cache: self.cache,
            cache_policy: self.cache_policy,
            profile_store,
            snapshotter_metrics: self
                .snapshotter_metrics
                .unwrap_or_else(|| Arc::new(SnapshotterMetrics::new())),
            auto_zran: self.auto_zran,
            access_tracer: self.access_tracer,
            metrics: Arc::new(ControllerMetrics::default()),
            grpc_socket: self.grpc_socket,
            mount_probe_timeout: self.mount_probe_timeout,
        }
    }
}

impl SystemController {
    /// Shortcut for tests that need a controller with no optional
    /// dependencies. Production code uses [`SystemControllerBuilder`].
    pub fn new(
        supervisor: Arc<DaemonSupervisor>,
        store: Arc<SnapshotStore>,
        cache: CacheManager,
        cache_policy: CacheGcPolicy,
    ) -> Self {
        SystemControllerBuilder::new(supervisor, store, cache, cache_policy).build()
    }

    /// Return live and persisted daemon records.
    pub async fn list_daemons(&self) -> Vec<DaemonStatusRecord> {
        self.supervisor.daemon_records().await
    }

    /// Return a daemon record by slug or exact image reference.
    pub async fn daemon_record(&self, id: &str) -> Option<DaemonStatusRecord> {
        self.supervisor.daemon_record(id).await
    }

    /// Explicitly spawn a daemon from the system-controller API.
    pub async fn spawn_daemon(
        &self,
        image_ref: &str,
        bootstrap: &Path,
    ) -> Result<DaemonStatusRecord> {
        let result = self.supervisor.spawn_instance(image_ref, bootstrap).await;
        self.metrics.record_daemon_spawn(result.is_err());
        result
    }

    /// Checkpoint live daemon records to the persisted record format
    /// (the basis a future FD-handoff upgrade would build on).
    pub async fn checkpoint_daemons(&self) -> Result<Vec<DaemonStatusRecord>> {
        self.supervisor.checkpoint_records().await
    }

    /// Replace all eligible in-process daemons.
    pub async fn upgrade_daemons(
        &self,
        options: DaemonUpgradeOptions,
    ) -> Result<DaemonUpgradeReport> {
        let result = self.supervisor.upgrade_instances(options).await;
        match &result {
            Ok(report) => self.metrics.record_daemon_upgrade(report),
            Err(_) => self.metrics.record_daemon_upgrade_failure(),
        }
        result
    }

    /// Replace one eligible in-process daemon by slug or image reference.
    pub async fn upgrade_daemon(
        &self,
        id: &str,
        options: DaemonUpgradeOptions,
    ) -> Result<DaemonUpgradeReport> {
        let result = self.supervisor.upgrade_instance(id, options).await;
        match &result {
            Ok(report) => self.metrics.record_daemon_upgrade(report),
            Err(_) => self.metrics.record_daemon_upgrade_failure(),
        }
        result
    }

    /// Return persisted snapshot records from the metadata store.
    pub fn snapshot_records(&self) -> Result<Vec<SnapshotInfo>> {
        self.store.list()
    }

    /// Return current cache usage without deleting anything.
    pub fn cache_usage(&self) -> Result<CacheUsage> {
        Ok(self.cache.scan()?)
    }

    /// Trigger cache GC using the controller's configured policy.
    pub async fn cache_gc(&self) -> Result<CacheGcReport> {
        let protected = self.supervisor.protected_cache_slugs().await;
        let report = self.cache.garbage_collect(&self.cache_policy, &protected)?;
        self.metrics
            .record_cache_gc(&report, self.cache_policy.dry_run);
        Ok(report)
    }

    /// Trigger cache GC with a one-shot policy override (the request-body
    /// policy of `POST /api/v1/cache/gc`) without mutating the configured
    /// policy.
    pub async fn cache_gc_with_policy(&self, policy: &CacheGcPolicy) -> Result<CacheGcReport> {
        let protected = self.supervisor.protected_cache_slugs().await;
        let report = self.cache.garbage_collect(policy, &protected)?;
        self.metrics.record_cache_gc(&report, policy.dry_run);
        Ok(report)
    }

    /// Store per-image prefetch file hints delivered by an NRI prefetch plugin.
    pub fn set_prefetch(&self, entries: Vec<PrefetchRequestEntry>) -> Result<PrefetchResponse> {
        let entries = entries.into_iter().map(|entry| {
            let files = normalize_prefetch_files(
                entry
                    .prefetch
                    .lines()
                    .chain(entry.files.iter().map(String::as_str)),
            );
            (entry.image, files)
        });
        let updated = set_runtime_prefetch(entries)?;
        Ok(PrefetchResponse { images: updated })
    }

    /// Persist and activate a structured prefetch profile.
    pub fn set_prefetch_profile(&self, profile: PrefetchProfile) -> Result<PrefetchResponse> {
        self.profile_store.put(&profile)?;
        let updated = set_runtime_prefetch([(profile.image.clone(), profile.prefetch_files())])?;
        if let Some(auto_zran) = &self.auto_zran {
            auto_zran.try_enqueue_profile(&profile);
        }
        Ok(PrefetchResponse { images: updated })
    }

    /// Reset the access-tracer `first_seen`/`last_event` baseline for every
    /// active mount of `image_ref`. Returns the number of mounts whose timer
    /// was reset, or `Ok(0)` when the tracer is disabled / the image has no
    /// open capture state. Called from the NRI optimizer plugin's
    /// `StartContainer` hook.
    pub fn access_tracer_start(&self, image_ref: &str) -> Result<usize> {
        match self.access_tracer.as_ref() {
            Some(tracer) => tracer.restart_image_timer(image_ref),
            None => Ok(0),
        }
    }

    /// Attach the access-tracer to the container's rootfs overlay mount,
    /// resolved from the container PID via `mountinfo`. This is the
    /// high-fidelity capture path: events fire with paths relative to the
    /// host-side overlay mount (e.g.
    /// `/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/<id>/rootfs/etc/nginx/nginx.conf`),
    /// so `record_event`'s prefix strip produces the in-container paths
    /// (e.g. `/etc/nginx/nginx.conf`) the auto-zran pipeline wants.
    ///
    /// The Prepare-time attach (on the snapshotter's lower snapshot dir)
    /// doesn't capture container reads — overlay resolves container paths in
    /// the container's namespace, not against the lower. This rootfs-time
    /// attach is what actually captures.
    ///
    /// Called by the NRI optimizer plugin's `StartContainer` hook with the
    /// container PID from the NRI Container message.
    pub fn access_tracer_attach_rootfs(&self, image_ref: &str, pid: u32) -> Result<bool> {
        let Some(tracer) = self.access_tracer.as_ref() else {
            return Ok(false);
        };
        let rootfs = host_rootfs_for_pid(pid)
            .with_context(|| format!("resolve host rootfs for pid {pid}"))?;
        // The holder is synthetic (there is no snapshot key on this path);
        // cleanup happens via mark_image_accelerated on conversion, or the
        // empty-capture settle for pods that die without producing events.
        tracer.attach(image_ref, &rootfs, &format!("nri-rootfs-pid-{pid}"))?;
        Ok(true)
    }

    /// Force-flush the access-tracer profile for `image_ref` regardless of
    /// timer state. Returns `Ok(true)` if a profile was flushed (i.e. at
    /// least `min_files` captured), `Ok(false)` otherwise. Called from the
    /// NRI optimizer plugin's `StopContainer` hook.
    pub fn access_tracer_settle(&self, image_ref: &str) -> Result<bool> {
        match self.access_tracer.as_ref() {
            Some(tracer) => tracer.settle_image(image_ref),
            None => Ok(false),
        }
    }

    /// Return all known prefetch hints.
    pub fn prefetch_entries(&self) -> Result<BTreeMap<String, Vec<String>>> {
        let mut entries = self
            .profile_store
            .list()?
            .into_iter()
            .map(|profile| (profile.image.clone(), profile.prefetch_files()))
            .collect::<BTreeMap<_, _>>();
        entries.extend(runtime_prefetch_records()?);
        Ok(entries)
    }
}

/// Serve the system-controller HTTP API on a Unix domain socket.
///
/// The API is unauthenticated by design (it includes `PUT /api/v1/auth` for
/// registry-credential injection and daemon spawn/upgrade controls), so
/// transport-level protection is the only protection: the socket is chmodded
/// to `0600` immediately after bind (a permissive umask must not widen it),
/// and a pre-existing socket that still answers connections is treated as a
/// live instance rather than silently hijacked.
pub async fn serve_unix(path: PathBuf, controller: SystemController) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create sysctl socket parent directory {}",
                parent.display()
            )
        })?;
    }
    if path.exists() {
        // Only reclaim the path if nothing is accepting on it (stale socket
        // from a crashed predecessor). Stealing a live instance's admin socket
        // silently redirects credential pushes to the wrong process.
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            anyhow::bail!(
                "sysctl socket {} is already served by a live process; refusing to steal it",
                path.display()
            );
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to remove stale sysctl socket {}", path.display()))?;
    }
    let listener = UnixListener::bind(&path)
        .await
        .with_context(|| format!("failed to bind sysctl socket {}", path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod sysctl socket {} to 0600", path.display()))?;
    }
    info!(path = %path.display(), "starting nydus system-controller API");

    // Serve over cyper-axum (hyper-on-compio) like the gRPC server, instead of a raw
    // `listener.accept()` loop: compio-driver's io_uring accept hits a multishot-accept
    // panic that aborts the whole snapshotter process.
    let app = axum::Router::new()
        .fallback(handle_request)
        .with_state(controller);
    cyper_axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

/// Bridge an axum request to the `route_request` dispatcher.
async fn handle_request(
    axum::extract::State(controller): axum::extract::State<SystemController>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => {
            return (
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            )
                .into_response();
        }
    };
    debug!(%method, %path, body_bytes = body.len(), "sysctl request received");
    let response = route_request(&controller, HttpRequest { method, path, body }).await;
    axum::response::Response::builder()
        .status(response.status)
        .header(axum::http::header::CONTENT_TYPE, response.content_type)
        .body(axum::body::Body::from(response.body))
        .unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

async fn route_request(controller: &SystemController, request: HttpRequest) -> HttpResponse {
    let path = request.path.split('?').next().unwrap_or(&request.path);
    match (request.method.as_str(), path) {
        ("GET", "/api/v1/daemons") | ("GET", "/api/v1/daemons/records") => {
            json_response(200, controller.list_daemons().await)
        }
        ("POST", "/api/v1/daemons") => handle_daemon_spawn(controller, &request.body).await,
        ("GET", "/api/v1/snapshots/records") => match controller.snapshot_records() {
            Ok(records) => json_response(200, records),
            Err(e) => error_response(500, e.to_string()),
        },
        ("POST", "/api/v1/daemons/upgrade") => {
            handle_daemon_upgrade(controller, None, &request.body).await
        }
        ("GET", "/api/v1/cache/usage") => match controller.cache_usage() {
            Ok(usage) => json_response(200, CacheUsageResponse::from(usage)),
            Err(e) => error_response(500, e.to_string()),
        },
        ("POST", "/api/v1/cache/gc") => handle_cache_gc(controller, &request.body).await,
        ("GET", "/api/v1/mounts/health") => match controller.supervisor.last_mount_health() {
            Some(report) => json_response(200, report),
            None => json_response(200, crate::daemon::MountHealthReport::default()),
        },
        ("POST", "/api/v1/mounts/health") => {
            let report = controller
                .supervisor
                .probe_mount_health(controller.mount_probe_timeout)
                .await;
            json_response(200, report)
        }
        ("GET", "/api/v1/prefetch") => match controller.prefetch_entries() {
            Ok(entries) => json_response(200, entries),
            Err(e) => error_response(500, e.to_string()),
        },
        ("PUT", "/api/v1/prefetch") => handle_prefetch_put(controller, &request.body),
        ("PUT", "/api/v1/prefetch/profile") => {
            handle_prefetch_profile_put(controller, &request.body)
        }
        ("POST", "/api/v1/access-tracer/start") => {
            handle_access_tracer_event(controller, &request.body, AccessTracerEvent::Start)
        }
        ("POST", "/api/v1/access-tracer/settle") => {
            handle_access_tracer_event(controller, &request.body, AccessTracerEvent::Settle)
        }
        ("GET", "/api/v1/auth") => match runtime_auth_records() {
            Ok(records) => json_response(200, records),
            Err(e) => error_response(500, e.to_string()),
        },
        ("PUT", "/api/v1/auth") => handle_auth_put(&request.body),
        ("GET", "/metrics") => metrics_response(controller).await,
        // Liveness: the sysctl server shares the compio event loop with the
        // gRPC server, so any reply at all proves the loop is responsive.
        ("GET", "/healthz") => json_response(200, serde_json::json!({ "status": "ok" })),
        ("GET", "/readyz") => handle_readyz(controller),
        ("GET", "/debug/allocator") => json_response(200, AllocatorStatsResponse::collect()),
        _ => route_dynamic_request(controller, &request.method, path, &request.body).await,
    }
}

/// Resolve a container PID to the host-side overlay rootfs mount path.
///
/// Canonicalizing `/proc/<pid>/root` directly returns `"/"` because the proc
/// magic symlink reads as the process's view of its root, so the
/// mount-namespace boundary is crossed via `mountinfo` strings instead. The
/// pure parsing logic lives in `find_rootfs_in_mountinfo` so it can be
/// unit-tested from fixtures rather than against a live `/proc`.
fn host_rootfs_for_pid(pid: u32) -> Result<PathBuf> {
    let container_info = std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))
        .with_context(|| format!("read /proc/{pid}/mountinfo"))?;
    let host_info =
        std::fs::read_to_string("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;
    find_rootfs_in_mountinfo(&container_info, &host_info)
        .with_context(|| format!("resolve host rootfs for pid {pid}"))
}

/// Pure-function side of `host_rootfs_for_pid`. Given the contents of
/// `/proc/<pid>/mountinfo` (the container's view) and
/// `/proc/self/mountinfo` (the host's), find the host-side mount-point of
/// the container's overlay rootfs.
///
/// Algorithm:
///
/// 1. In the container's mountinfo find the line whose mount-point is
///    `"/"` (its rootfs). Capture its `st_dev` (`MAJOR:MINOR`) AND the
///    `lowerdir=` suffix of its super-options. `st_dev` alone is not
///    enough on a node with multiple overlay mounts because all overlay
///    mounts share the same anon block-device family `0:N`; the
///    `lowerdir=` chain disambiguates because each container's overlay
///    pulls a unique snapshot chain.
/// 2. In the host's mountinfo find the first matching mount where:
///    - `st_dev` matches AND
///    - the mount-point looks like a containerd CRI runtime rootfs
///      (`…/io.containerd.runtime.*/rootfs`) AND
///    - the `lowerdir=` super-option matches the container's.
///
/// The previous version keyed only on `st_dev` + path-shape; on a node
/// with two containers of the same image we'd return the first match
/// — possibly the *other* container's rootfs — and silently capture the
/// wrong process's reads.
fn find_rootfs_in_mountinfo(container_info: &str, host_info: &str) -> Result<PathBuf> {
    let (device, lowerdir) = container_info
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // mountinfo schema: [id parent st_dev root mount_point options ... - fs_type source super_options]
            if fields.len() < 5 || fields[4] != "/" {
                return None;
            }
            Some((fields[2].to_string(), extract_lowerdir(line)))
        })
        .context("container has no '/' mount in mountinfo")?;

    for line in host_info.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 || fields[2] != device {
            continue;
        }
        let mount_point = fields[4];
        if !mount_point.contains("/io.containerd.runtime.") || !mount_point.ends_with("/rootfs") {
            continue;
        }
        // Always require matching lowerdir when the container exposed
        // one. If the container's "/" wasn't overlay (rare but possible
        // in unprivileged runtimes) we accept any path-shape match.
        match (&lowerdir, extract_lowerdir(line)) {
            (Some(want), Some(have)) if want == &have => return Ok(PathBuf::from(mount_point)),
            (Some(_), Some(_)) => continue,
            (Some(_), None) => continue,
            (None, _) => return Ok(PathBuf::from(mount_point)),
        }
    }
    anyhow::bail!("no host rootfs overlay mount matches device {device} + lowerdir {lowerdir:?}")
}

/// Extract the `lowerdir=…` super-option from one mountinfo line. Returns
/// `None` for non-overlay mounts or lines that don't include the suffix.
fn extract_lowerdir(line: &str) -> Option<String> {
    let opts = line.split(" - ").nth(1)?;
    for token in opts.split([',', ' ']) {
        if let Some(rest) = token.strip_prefix("lowerdir=") {
            return Some(rest.to_string());
        }
    }
    None
}

fn handle_auth_put(body: &[u8]) -> HttpResponse {
    let entries = match serde_json::from_slice::<Vec<RuntimeAuthRequest>>(body) {
        Ok(entries) => entries,
        Err(e) => return error_response(400, format!("invalid auth request: {e}")),
    };
    match set_runtime_auth(entries) {
        Ok(registries) => json_response(200, RuntimeAuthResponse { registries }),
        Err(e) => error_response(500, e.to_string()),
    }
}

async fn handle_daemon_spawn(controller: &SystemController, body: &[u8]) -> HttpResponse {
    let req = match serde_json::from_slice::<DaemonSpawnRequest>(body) {
        Ok(req) => req,
        Err(e) => return error_response(400, format!("invalid daemon spawn request: {e}")),
    };
    match controller
        .spawn_daemon(&req.image_ref, req.bootstrap.as_path())
        .await
    {
        Ok(record) => json_response(200, record),
        Err(e) => controller_error_response(e),
    }
}

async fn handle_daemon_upgrade(
    controller: &SystemController,
    id: Option<&str>,
    body: &[u8],
) -> HttpResponse {
    let req = if body.is_empty() {
        DaemonUpgradeRequest::default()
    } else {
        match serde_json::from_slice::<DaemonUpgradeRequest>(body) {
            Ok(req) => req,
            Err(e) => return error_response(400, format!("invalid daemon upgrade request: {e}")),
        }
    };
    let options = DaemonUpgradeOptions {
        allow_active: req.allow_active,
    };
    let result = match id {
        Some(id) => controller.upgrade_daemon(id, options).await,
        None => controller.upgrade_daemons(options).await,
    };
    match result {
        Ok(report) => json_response(
            200,
            DaemonUpgradeResponse {
                status: upgrade_status(&report).to_string(),
                report,
            },
        ),
        Err(e) => controller_error_response(e),
    }
}

fn handle_prefetch_put(controller: &SystemController, body: &[u8]) -> HttpResponse {
    let entries = match serde_json::from_slice::<Vec<PrefetchRequestEntry>>(body) {
        Ok(entries) => entries,
        Err(e) => return error_response(400, format!("invalid prefetch request: {e}")),
    };
    match controller.set_prefetch(entries) {
        Ok(response) => json_response(200, response),
        Err(e) => error_response(500, e.to_string()),
    }
}

fn handle_prefetch_profile_put(controller: &SystemController, body: &[u8]) -> HttpResponse {
    let profile = match serde_json::from_slice::<PrefetchProfile>(body) {
        Ok(profile) => profile,
        Err(e) => return error_response(400, format!("invalid prefetch profile: {e}")),
    };
    match controller.set_prefetch_profile(profile) {
        Ok(response) => json_response(200, response),
        Err(e) => controller_error_response(e),
    }
}

#[derive(Clone, Copy)]
enum AccessTracerEvent {
    Start,
    Settle,
}

fn handle_access_tracer_event(
    controller: &SystemController,
    body: &[u8],
    event: AccessTracerEvent,
) -> HttpResponse {
    let req = match serde_json::from_slice::<AccessTracerEventRequest>(body) {
        Ok(req) => req,
        Err(e) => return error_response(400, format!("invalid access-tracer request: {e}")),
    };
    let image = req.image.trim();
    if image.is_empty() {
        return error_response(400, "access-tracer request missing 'image'".to_string());
    }
    match event {
        AccessTracerEvent::Start => {
            // Optional rootfs attach when caller provides a container PID
            // (NRI optimizer plugin path). On failure we still report the
            // baseline reset result so the timer-only path still works.
            let rootfs_attached = match req.pid {
                Some(pid) => match controller.access_tracer_attach_rootfs(image, pid) {
                    Ok(applied) => applied,
                    Err(e) => {
                        debug!(image, pid, error = %e, "access-tracer rootfs attach failed");
                        false
                    }
                },
                None => false,
            };
            match controller.access_tracer_start(image) {
                Ok(mounts) => json_response(
                    200,
                    AccessTracerEventResponse {
                        image: image.to_string(),
                        applied: mounts > 0 || rootfs_attached,
                        mounts,
                        flushed: false,
                        rootfs_attached,
                    },
                ),
                Err(e) => controller_error_response(e),
            }
        }
        AccessTracerEvent::Settle => match controller.access_tracer_settle(image) {
            Ok(flushed) => json_response(
                200,
                AccessTracerEventResponse {
                    image: image.to_string(),
                    applied: flushed,
                    mounts: 0,
                    flushed,
                    rootfs_attached: false,
                },
            ),
            Err(e) => controller_error_response(e),
        },
    }
}

async fn route_dynamic_request(
    controller: &SystemController,
    method: &str,
    path: &str,
    body: &[u8],
) -> HttpResponse {
    if let Some(id) = path.strip_prefix("/api/v1/daemons/") {
        if let Some((id, suffix)) = id.split_once('/') {
            if method == "POST" && suffix == "cache/gc" {
                // The blob cache is a single global root shared by every daemon;
                // there is no per-daemon partition to GC. Silently running a
                // global GC here misrepresented what happened, so point callers
                // at the global endpoint instead.
                return error_response(
                    400,
                    format!(
                        "per-daemon cache GC is not supported (the blob cache is global); \
                         use POST /api/v1/cache/gc instead of /api/v1/daemons/{id}/cache/gc"
                    ),
                );
            }
            if method == "POST" && suffix == "upgrade" {
                return handle_daemon_upgrade(controller, Some(id), body).await;
            }
            if method == "GET" && suffix == "backend" {
                return match controller.daemon_record(id).await {
                    Some(record) => json_response(200, DaemonBackendResponse::from(record)),
                    None => error_response(404, format!("daemon {id} not found")),
                };
            }
        } else if method == "GET" {
            return match controller.daemon_record(id).await {
                Some(record) => json_response(200, record),
                None => error_response(404, format!("daemon {id} not found")),
            };
        }
    }
    error_response(404, format!("unknown endpoint {method} {path}"))
}

async fn handle_cache_gc(controller: &SystemController, body: &[u8]) -> HttpResponse {
    let result = if body.is_empty() {
        controller.cache_gc().await
    } else {
        let req = match serde_json::from_slice::<CacheGcRequest>(body) {
            Ok(req) => req,
            Err(e) => return error_response(400, format!("invalid cache GC request: {e}")),
        };
        let policy = match req.into_policy() {
            Ok(policy) => policy,
            Err(e) => return error_response(400, e.to_string()),
        };
        controller.cache_gc_with_policy(&policy).await
    };

    match result {
        Ok(report) => json_response(200, CacheGcReportResponse::from(report)),
        Err(e) => error_response(500, e.to_string()),
    }
}

/// Readiness: the snapshotter is ready once the containerd proxy-plugin gRPC
/// socket accepts connections. A UDS connect is cheap and hits no store or
/// daemon state, so kubelet-frequency probing cannot amplify I/O.
fn handle_readyz(controller: &SystemController) -> HttpResponse {
    let Some(socket) = controller.grpc_socket.as_ref() else {
        return error_response(503, "not ready: gRPC socket path not configured");
    };
    match std::os::unix::net::UnixStream::connect(socket) {
        Ok(_) => json_response(200, serde_json::json!({ "status": "ready" })),
        Err(e) => error_response(
            503,
            format!(
                "not ready: gRPC socket {} not accepting connections: {e}",
                socket.display()
            ),
        ),
    }
}

fn json_response<T: Serialize>(status: u16, body: T) -> HttpResponse {
    match serde_json::to_vec(&body) {
        Ok(body) => HttpResponse {
            status,
            content_type: "application/json",
            body,
        },
        Err(e) => error_response(500, format!("failed to encode response: {e}")),
    }
}

fn error_response(status: u16, message: impl Into<String>) -> HttpResponse {
    let body = serde_json::to_vec(&ErrorResponse {
        error: message.into(),
    })
    .unwrap_or_else(|_| b"{\"error\":\"failed to encode error\"}".to_vec());
    HttpResponse {
        status,
        content_type: "application/json",
        body,
    }
}

fn controller_error_response(error: anyhow::Error) -> HttpResponse {
    let message = error.to_string();
    let status = if message.contains("not found") {
        404
    } else if message.contains("must be non-empty")
        || message.contains("is missing")
        || message.contains("already serving bootstrap")
        || message.contains("prefetch profile")
    {
        400
    } else {
        500
    };
    error_response(status, message)
}

fn upgrade_status(report: &DaemonUpgradeReport) -> &'static str {
    if report.failed > 0 {
        "partial_failure"
    } else if report.upgraded > 0 {
        "upgraded"
    } else if report.skipped > 0 {
        "skipped"
    } else {
        "no_daemons"
    }
}

async fn metrics_response(controller: &SystemController) -> HttpResponse {
    let daemons = controller.list_daemons().await;
    let records = match controller.snapshot_records() {
        Ok(records) => records,
        Err(e) => return error_response(500, e.to_string()),
    };
    let cache = match controller.cache_usage() {
        Ok(usage) => usage,
        Err(e) => return error_response(500, e.to_string()),
    };
    let metrics = controller.metrics.snapshot();

    let mut snapshot_counts: BTreeMap<&'static str, u64> =
        BTreeMap::from([("active", 0), ("committed", 0), ("view", 0), ("unknown", 0)]);
    for record in &records {
        let kind = snapshot_kind_label(&record.kind);
        *snapshot_counts.entry(kind).or_default() += 1;
    }

    let mut cache_artifacts: BTreeMap<&'static str, (u64, u64)> = BTreeMap::from([
        ("blob_data", (0, 0)),
        ("blob_meta", (0, 0)),
        ("bootstrap", (0, 0)),
        ("chunk_map", (0, 0)),
        ("other", (0, 0)),
    ]);
    for entry in &cache.entries {
        let (files, bytes) = cache_artifacts
            .entry(cache_artifact_label(entry.kind))
            .or_default();
        *files += 1;
        *bytes += entry.size;
    }

    let mut body = String::new();
    body.push_str("# HELP nydus_snapshotter_daemons Active in-process nydus daemon instances.\n");
    body.push_str("# TYPE nydus_snapshotter_daemons gauge\n");
    let live_daemon_count = daemons.iter().filter(|d| d.live).count();
    push_metric(&mut body, "nydus_snapshotter_daemons", live_daemon_count);

    body.push_str(
        "# HELP nydus_snapshotter_parked_fds Fds parked in the systemd fd store for failover.\n",
    );
    body.push_str("# TYPE nydus_snapshotter_parked_fds gauge\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_parked_fds",
        controller.supervisor.parked_fd_count(),
    );

    if let Some(health) = controller.supervisor.last_mount_health() {
        body.push_str(
            "# HELP nydus_snapshotter_dead_mounts Live daemon mounts that failed the last health probe.\n",
        );
        body.push_str("# TYPE nydus_snapshotter_dead_mounts gauge\n");
        push_metric(&mut body, "nydus_snapshotter_dead_mounts", health.dead);

        body.push_str(
            "# HELP nydus_snapshotter_mount_healthy Per-mount health from the last probe pass (1 healthy, 0 dead).\n",
        );
        body.push_str("# TYPE nydus_snapshotter_mount_healthy gauge\n");
        for result in &health.results {
            push_labeled_metric(
                &mut body,
                "nydus_snapshotter_mount_healthy",
                &[("slug", &result.slug), ("image", &result.image_ref)],
                u64::from(result.healthy),
            );
        }
    }
    body.push_str("# HELP nydus_snapshotter_daemon_refcount Current refcount per live daemon.\n");
    body.push_str("# TYPE nydus_snapshotter_daemon_refcount gauge\n");
    for d in daemons.iter().filter(|d| d.live) {
        push_labeled_metric(
            &mut body,
            "nydus_snapshotter_daemon_refcount",
            &[("slug", &d.slug), ("image", &d.image_ref)],
            d.refcount as u64,
        );
    }
    body.push_str(
        "# HELP nydus_snapshotter_daemon_holders Tracked holder keys per live daemon (refcount minus holders = restart ballast).\n",
    );
    body.push_str("# TYPE nydus_snapshotter_daemon_holders gauge\n");
    for d in daemons.iter().filter(|d| d.live) {
        push_labeled_metric(
            &mut body,
            "nydus_snapshotter_daemon_holders",
            &[("slug", &d.slug), ("image", &d.image_ref)],
            d.holders as u64,
        );
    }

    body.push_str(
        "# HELP nydus_snapshotter_mount_probe_timeouts_total Mount health probes that timed out.\n",
    );
    body.push_str("# TYPE nydus_snapshotter_mount_probe_timeouts_total counter\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_mount_probe_timeouts_total",
        controller.supervisor.mount_probe_timeouts_total(),
    );

    body.push_str("# HELP nydusd_counts The counts of nydus daemon.\n");
    body.push_str("# TYPE nydusd_counts gauge\n");
    push_labeled_metric(
        &mut body,
        "nydusd_counts",
        &[("version", "in-process")],
        live_daemon_count,
    );

    body.push_str("# HELP nydusd_lifetime_event_counts The lifetime events of nydus daemon.\n");
    body.push_str("# TYPE nydusd_lifetime_event_counts counter\n");
    push_labeled_metric(
        &mut body,
        "nydusd_lifetime_event_counts",
        &[("event", "spawn")],
        metrics.daemon_spawn_runs_total,
    );
    push_labeled_metric(
        &mut body,
        "nydusd_lifetime_event_counts",
        &[("event", "upgrade")],
        metrics.daemon_upgrade_runs_total,
    );

    body.push_str(
        "# HELP nydus_snapshotter_daemon_info Metadata about active in-process daemons.\n",
    );
    body.push_str("# TYPE nydus_snapshotter_daemon_info gauge\n");
    body.push_str("# HELP nydusd_image_info Mapping of nydus daemon to served image references.\n");
    body.push_str("# TYPE nydusd_image_info gauge\n");
    for daemon in daemons.into_iter().filter(|d| d.live) {
        push_labeled_metric(
            &mut body,
            "nydus_snapshotter_daemon_info",
            &[
                ("image_ref", daemon.image_ref.as_str()),
                ("mountpoint", daemon.mountpoint.to_str().unwrap_or_default()),
            ],
            1,
        );
        push_labeled_metric(
            &mut body,
            "nydusd_image_info",
            &[
                ("daemon_id", daemon.slug.as_str()),
                ("image_ref", daemon.image_ref.as_str()),
            ],
            1,
        );
    }

    body.push_str("# HELP nydus_snapshotter_daemon_spawn_runs_total Daemon spawn requests handled by the system controller.\n");
    body.push_str("# TYPE nydus_snapshotter_daemon_spawn_runs_total counter\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_daemon_spawn_runs_total",
        metrics.daemon_spawn_runs_total,
    );
    body.push_str("# HELP nydus_snapshotter_daemon_spawn_failures_total Failed daemon spawn requests handled by the system controller.\n");
    body.push_str("# TYPE nydus_snapshotter_daemon_spawn_failures_total counter\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_daemon_spawn_failures_total",
        metrics.daemon_spawn_failures_total,
    );
    body.push_str("# HELP nydus_snapshotter_daemon_upgrade_runs_total Daemon upgrade requests handled by the system controller.\n");
    body.push_str("# TYPE nydus_snapshotter_daemon_upgrade_runs_total counter\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_daemon_upgrade_runs_total",
        metrics.daemon_upgrade_runs_total,
    );
    body.push_str("# HELP nydus_snapshotter_daemon_upgrade_failures_total Failed daemon upgrade attempts observed by the system controller.\n");
    body.push_str("# TYPE nydus_snapshotter_daemon_upgrade_failures_total counter\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_daemon_upgrade_failures_total",
        metrics.daemon_upgrade_failures_total,
    );

    body.push_str("# HELP nydus_snapshotter_snapshots Persisted snapshot records.\n");
    body.push_str("# TYPE nydus_snapshotter_snapshots gauge\n");
    push_metric(&mut body, "nydus_snapshotter_snapshots", records.len());
    body.push_str("# HELP nydus_snapshotter_snapshots_by_kind Persisted snapshot records by lifecycle kind.\n");
    body.push_str("# TYPE nydus_snapshotter_snapshots_by_kind gauge\n");
    for (kind, count) in snapshot_counts {
        push_labeled_metric(
            &mut body,
            "nydus_snapshotter_snapshots_by_kind",
            &[("kind", kind)],
            count,
        );
    }

    body.push_str(
        "# HELP nydus_snapshotter_cache_bytes Blob cache bytes under the configured cache root.\n",
    );
    body.push_str("# TYPE nydus_snapshotter_cache_bytes gauge\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_cache_bytes",
        cache.total_bytes,
    );
    body.push_str("# HELP nydus_snapshotter_cache_files Blob cache file count under the configured cache root.\n");
    body.push_str("# TYPE nydus_snapshotter_cache_files gauge\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_cache_files",
        cache.total_files,
    );
    body.push_str("# HELP nydus_snapshotter_cache_artifact_bytes Cache bytes by artifact kind.\n");
    body.push_str("# TYPE nydus_snapshotter_cache_artifact_bytes gauge\n");
    for (kind, (_files, bytes)) in &cache_artifacts {
        push_labeled_metric(
            &mut body,
            "nydus_snapshotter_cache_artifact_bytes",
            &[("kind", kind)],
            *bytes,
        );
    }
    body.push_str(
        "# HELP nydus_snapshotter_cache_artifact_files Cache file count by artifact kind.\n",
    );
    body.push_str("# TYPE nydus_snapshotter_cache_artifact_files gauge\n");
    for (kind, (files, _bytes)) in &cache_artifacts {
        push_labeled_metric(
            &mut body,
            "nydus_snapshotter_cache_artifact_files",
            &[("kind", kind)],
            *files,
        );
    }

    body.push_str("# HELP nydus_snapshotter_cache_gc_runs_total Cache GC runs triggered by the sysctl controller.\n");
    body.push_str("# TYPE nydus_snapshotter_cache_gc_runs_total counter\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_cache_gc_runs_total",
        metrics.cache_gc_runs_total,
    );
    body.push_str("# HELP nydus_snapshotter_cache_gc_removed_files_total Cache files removed by sysctl-triggered GC.\n");
    body.push_str("# TYPE nydus_snapshotter_cache_gc_removed_files_total counter\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_cache_gc_removed_files_total",
        metrics.cache_gc_removed_files_total,
    );
    body.push_str("# HELP nydus_snapshotter_cache_gc_removed_bytes_total Cache bytes removed by sysctl-triggered GC.\n");
    body.push_str("# TYPE nydus_snapshotter_cache_gc_removed_bytes_total counter\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_cache_gc_removed_bytes_total",
        metrics.cache_gc_removed_bytes_total,
    );
    body.push_str("# HELP nydus_snapshotter_cache_gc_failures_total Cache GC removal failures observed by the sysctl controller.\n");
    body.push_str("# TYPE nydus_snapshotter_cache_gc_failures_total counter\n");
    push_metric(
        &mut body,
        "nydus_snapshotter_cache_gc_failures_total",
        metrics.cache_gc_failures_total,
    );

    // "In use" means backing a live daemon (instance or live record), not
    // merely present on disk — the same protection set cache GC honors.
    let protected = controller.supervisor.protected_cache_slugs().await;
    let blobs_in_use = cache
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == crate::cache::CacheArtifactKind::BlobData
                && entry
                    .relative_path
                    .components()
                    .next()
                    .and_then(|c| c.as_os_str().to_str())
                    .is_some_and(|slug| protected.contains(slug))
        })
        .count() as u64;
    body.push_str(
        &controller
            .snapshotter_metrics
            .render_prometheus(CacheMetricSnapshot {
                total_bytes: cache.total_bytes,
                gc: Some(crate::metrics::CacheGcCounters {
                    deleted_blobs: metrics.cache_gc_removed_files_total,
                    deletion_errors: metrics.cache_gc_failures_total,
                    blobs_in_use,
                }),
            }),
    );

    HttpResponse {
        status: 200,
        content_type: "text/plain; version=0.0.4",
        body: body.into_bytes(),
    }
}

fn push_metric(body: &mut String, name: &str, value: impl IntoMetricValue) {
    body.push_str(name);
    body.push(' ');
    body.push_str(&value.into_metric_value());
    body.push('\n');
}

fn push_labeled_metric(
    body: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    value: impl IntoMetricValue,
) {
    body.push_str(name);
    body.push('{');
    for (idx, (key, value)) in labels.iter().enumerate() {
        if idx > 0 {
            body.push(',');
        }
        body.push_str(key);
        body.push_str("=\"");
        body.push_str(&escape_label_value(value));
        body.push('"');
    }
    body.push_str("} ");
    body.push_str(&value.into_metric_value());
    body.push('\n');
}

trait IntoMetricValue {
    fn into_metric_value(self) -> String;
}

impl IntoMetricValue for usize {
    fn into_metric_value(self) -> String {
        self.to_string()
    }
}

impl IntoMetricValue for u64 {
    fn into_metric_value(self) -> String {
        self.to_string()
    }
}

impl IntoMetricValue for i32 {
    fn into_metric_value(self) -> String {
        self.to_string()
    }
}

fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

fn snapshot_kind_label(kind: &str) -> &'static str {
    match kind {
        "kind_active" => "active",
        "kind_committed" => "committed",
        "kind_view" => "view",
        _ => "unknown",
    }
}

fn cache_artifact_label(kind: CacheArtifactKind) -> &'static str {
    match kind {
        CacheArtifactKind::BlobData => "blob_data",
        CacheArtifactKind::BlobMeta => "blob_meta",
        CacheArtifactKind::ChunkMap => "chunk_map",
        CacheArtifactKind::Bootstrap => "bootstrap",
        CacheArtifactKind::Other => "other",
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Response body for `GET /debug/allocator`.
///
/// The Go snapshotter exposed `net/http/pprof`; there is no idiomatic
/// equivalent on compio (io_uring) and tokio-console doesn't apply either,
/// so instead of porting pprof this endpoint surfaces cheap, read-only
/// allocator/process memory stats. The binaries link `mimalloc` as the
/// global allocator (see `bin/containerd-nydus.rs`), but the crate is
/// pulled in *without* its `extended` feature, so `mi_stats_*` /
/// `mi_process_info` are not reachable without a `Cargo.toml` change. Until
/// that feature is opted in, this reports portable process RSS instead:
/// `/proc/self/status` on Linux, `None` elsewhere. See `docs/operations.md`
/// for `perf`/`samply` CPU-profiling guidance.
#[derive(Clone, Debug, Default, Serialize)]
struct AllocatorStatsResponse {
    /// Where the numbers below came from, e.g. `"proc_self_status"` or
    /// `"unavailable"`.
    source: &'static str,
    /// Whether mimalloc's own extended stats (`mi_process_info`,
    /// `mi_stats_print_out`) are reachable in this build. Always `false`
    /// today — the `mimalloc` dependency doesn't enable the `extended`
    /// Cargo feature.
    mimalloc_extended_stats_available: bool,
    /// Current resident set size, in bytes (`VmRSS`).
    current_rss_bytes: Option<u64>,
    /// Peak resident set size ("high water mark"), in bytes (`VmHWM`).
    peak_rss_bytes: Option<u64>,
    /// Current virtual memory size, in bytes (`VmSize`).
    virtual_size_bytes: Option<u64>,
    /// Human-readable caveat about what is/isn't included.
    note: &'static str,
}

impl AllocatorStatsResponse {
    fn collect() -> Self {
        let stats = process_memory_stats();
        Self {
            source: stats.source,
            mimalloc_extended_stats_available: false,
            current_rss_bytes: stats.current_rss,
            peak_rss_bytes: stats.peak_rss,
            virtual_size_bytes: stats.virtual_size,
            note: stats.note,
        }
    }
}

/// Portable process memory snapshot. Named fields (rather than a positional
/// tuple) so the three same-typed `Option<u64>` sizes can't be silently
/// transposed by a future edit — the compiler checks them by name.
struct ProcMemStats {
    /// Where the numbers came from, e.g. `"proc_self_status"` or `"unavailable"`.
    source: &'static str,
    /// Current resident set size, in bytes (`VmRSS`).
    current_rss: Option<u64>,
    /// Peak resident set size, in bytes (`VmHWM`).
    peak_rss: Option<u64>,
    /// Current virtual memory size, in bytes (`VmSize`).
    virtual_size: Option<u64>,
    /// Human-readable caveat about what is/isn't included.
    note: &'static str,
}

/// Read a portable process memory snapshot.
///
/// Linux reads `/proc/self/status`, which reports resident/peak/virtual
/// sizes in kB regardless of allocator; non-Linux targets (macOS dev boxes)
/// have no equivalently cheap portable syscall wired up here, so they get
/// an explicit `"unavailable"` source rather than silently-wrong zeros.
#[cfg(target_os = "linux")]
fn process_memory_stats() -> ProcMemStats {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to read /proc/self/status for /debug/allocator");
            return ProcMemStats {
                source: "unavailable",
                current_rss: None,
                peak_rss: None,
                virtual_size: None,
                note: "failed to read /proc/self/status",
            };
        }
    };
    let (current_rss, peak_rss, virtual_size) = parse_proc_status_memory(&status);
    ProcMemStats {
        source: "proc_self_status",
        current_rss,
        peak_rss,
        virtual_size,
        note: "portable RSS via /proc/self/status; mimalloc extended stats not enabled",
    }
}

#[cfg(not(target_os = "linux"))]
fn process_memory_stats() -> ProcMemStats {
    ProcMemStats {
        source: "unavailable",
        current_rss: None,
        peak_rss: None,
        virtual_size: None,
        note: "no portable RSS source wired up for this platform; mimalloc extended stats not enabled",
    }
}

/// Parse `VmRSS`/`VmHWM`/`VmSize` (all in kB in `/proc/self/status`) into
/// byte counts. Pure function so it can be unit-tested from a fixture
/// string without touching `/proc` (and so it also runs on macOS CI).
#[allow(dead_code)]
fn parse_proc_status_memory(status: &str) -> (Option<u64>, Option<u64>, Option<u64>) {
    let mut current = None;
    let mut peak = None;
    let mut virt = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            current = parse_status_kb_field(rest);
        } else if let Some(rest) = line.strip_prefix("VmHWM:") {
            peak = parse_status_kb_field(rest);
        } else if let Some(rest) = line.strip_prefix("VmSize:") {
            virt = parse_status_kb_field(rest);
        }
    }
    (current, peak, virt)
}

/// Parse the `"  1234 kB"` tail of a `/proc/self/status` field into bytes.
#[allow(dead_code)]
fn parse_status_kb_field(field: &str) -> Option<u64> {
    let kb: u64 = field.split_whitespace().next()?.parse().ok()?;
    kb.checked_mul(1024)
}

#[derive(Clone, Debug, Deserialize)]
struct DaemonSpawnRequest {
    image_ref: String,
    bootstrap: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct DaemonUpgradeRequest {
    #[serde(default)]
    allow_active: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrefetchRequestEntry {
    pub image: String,
    #[serde(default)]
    pub prefetch: String,
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PrefetchResponse {
    images: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct AccessTracerEventRequest {
    image: String,
    /// Container PID. When set on `/start`, the snapshotter additionally
    /// attaches the access-tracer to `/proc/<pid>/root` so it captures the
    /// container's reads on the overlay rootfs mount (not just the lower
    /// snapshot dir).
    #[serde(default)]
    pid: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
struct AccessTracerEventResponse {
    image: String,
    applied: bool,
    mounts: usize,
    flushed: bool,
    /// True when `/start` also performed a rootfs attach via `pid`.
    #[serde(default)]
    rootfs_attached: bool,
}

#[derive(Clone, Debug, Serialize)]
struct RuntimeAuthResponse {
    registries: usize,
}

#[derive(Serialize)]
struct DaemonUpgradeResponse {
    status: String,
    report: DaemonUpgradeReport,
}

#[derive(Serialize)]
struct DaemonBackendResponse {
    image_ref: String,
    slug: String,
    bootstrap: PathBuf,
    mountpoint: PathBuf,
    backend: &'static str,
}

impl From<DaemonStatusRecord> for DaemonBackendResponse {
    fn from(value: DaemonStatusRecord) -> Self {
        Self {
            image_ref: value.image_ref,
            slug: value.slug,
            bootstrap: value.bootstrap,
            mountpoint: value.mountpoint,
            backend: "registry",
        }
    }
}

#[derive(Deserialize)]
struct CacheGcRequest {
    max_age: Option<String>,
    max_bytes: Option<u64>,
    dry_run: Option<bool>,
}

impl CacheGcRequest {
    fn into_policy(self) -> Result<CacheGcPolicy> {
        Ok(CacheGcPolicy {
            max_age: self
                .max_age
                .as_deref()
                .map(crate::cache::parse_duration)
                .transpose()?,
            max_bytes: self.max_bytes,
            dry_run: self.dry_run.unwrap_or(false),
        })
    }
}

#[derive(Serialize)]
struct CacheUsageResponse {
    total_bytes: u64,
    total_files: usize,
    entries: Vec<CacheEntryResponse>,
}

impl From<CacheUsage> for CacheUsageResponse {
    fn from(value: CacheUsage) -> Self {
        Self {
            total_bytes: value.total_bytes,
            total_files: value.total_files,
            entries: value
                .entries
                .into_iter()
                .map(CacheEntryResponse::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct CacheEntryResponse {
    path: String,
    relative_path: String,
    size: u64,
    modified_unix: Option<u64>,
    accessed_unix: Option<u64>,
    kind: &'static str,
}

impl From<crate::cache::CacheEntry> for CacheEntryResponse {
    fn from(value: crate::cache::CacheEntry) -> Self {
        Self {
            path: value.path.display().to_string(),
            relative_path: value.relative_path.display().to_string(),
            size: value.size,
            modified_unix: value.modified.and_then(system_time_secs),
            accessed_unix: value.accessed.and_then(system_time_secs),
            kind: match value.kind {
                crate::cache::CacheArtifactKind::BlobData => "blob_data",
                crate::cache::CacheArtifactKind::BlobMeta => "blob_meta",
                crate::cache::CacheArtifactKind::ChunkMap => "chunk_map",
                crate::cache::CacheArtifactKind::Bootstrap => "bootstrap",
                crate::cache::CacheArtifactKind::Other => "other",
            },
        }
    }
}

#[derive(Serialize)]
struct CacheGcReportResponse {
    scanned_files: usize,
    scanned_bytes: u64,
    removed_files: usize,
    removed_bytes: u64,
    removals: Vec<CacheGcRemovalResponse>,
    failures: Vec<CacheGcFailureResponse>,
}

impl From<CacheGcReport> for CacheGcReportResponse {
    fn from(value: CacheGcReport) -> Self {
        Self {
            scanned_files: value.scanned_files,
            scanned_bytes: value.scanned_bytes,
            removed_files: value.removed_files,
            removed_bytes: value.removed_bytes,
            removals: value
                .removals
                .into_iter()
                .map(CacheGcRemovalResponse::from)
                .collect(),
            failures: value
                .failures
                .into_iter()
                .map(CacheGcFailureResponse::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct CacheGcRemovalResponse {
    path: String,
    size: u64,
    dry_run: bool,
}

impl From<crate::cache::CacheGcRemoval> for CacheGcRemovalResponse {
    fn from(value: crate::cache::CacheGcRemoval) -> Self {
        Self {
            path: value.path.display().to_string(),
            size: value.size,
            dry_run: value.dry_run,
        }
    }
}

#[derive(Serialize)]
struct CacheGcFailureResponse {
    path: String,
    error: String,
}

impl From<crate::cache::CacheGcFailure> for CacheGcFailureResponse {
    fn from(value: crate::cache::CacheGcFailure) -> Self {
        Self {
            path: value.path.display().to_string(),
            error: value.error,
        }
    }
}

fn system_time_secs(t: SystemTime) -> Option<u64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SnapshotterConfig;
    use crate::store::SnapshotKind;
    use std::collections::HashMap;
    use std::time::Duration;
    use tempfile::tempdir;

    fn test_controller(root: PathBuf) -> SystemController {
        let mut config = SnapshotterConfig::default();
        config.snapshotter.root = root.clone();
        config.snapshotter.cache.work_dir = root.join("cache");
        let store = Arc::new(SnapshotStore::open(&root.join("metadata.fjall")).unwrap());
        SystemController::new(
            Arc::new(DaemonSupervisor::new(config.clone())),
            store,
            CacheManager::from_config(&config),
            CacheGcPolicy::default(),
        )
    }

    #[compio::test]
    async fn list_daemons_is_empty_for_new_controller() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        assert!(controller.list_daemons().await.is_empty());
    }

    #[compio::test]
    async fn healthz_always_reports_ok() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/healthz".to_string(),
                body: Vec::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["status"], "ok");
    }

    #[compio::test]
    async fn readyz_tracks_grpc_socket_liveness() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("grpc.sock");
        let mut config = SnapshotterConfig::default();
        config.snapshotter.root = dir.path().to_path_buf();
        config.snapshotter.cache.work_dir = dir.path().join("cache");
        let store = Arc::new(SnapshotStore::open(&dir.path().join("metadata.fjall")).unwrap());
        let controller = SystemControllerBuilder::new(
            Arc::new(DaemonSupervisor::new(config.clone())),
            store,
            CacheManager::from_config(&config),
            CacheGcPolicy::default(),
        )
        .with_grpc_socket(socket.clone())
        .build();

        let readyz = |controller: &SystemController| {
            let controller = controller.clone();
            async move {
                route_request(
                    &controller,
                    HttpRequest {
                        method: "GET".to_string(),
                        path: "/readyz".to_string(),
                        body: Vec::new(),
                    },
                )
                .await
            }
        };

        // Before the gRPC listener binds: not ready.
        assert_eq!(readyz(&controller).await.status, 503);

        // Once something accepts on the socket: ready.
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert_eq!(readyz(&controller).await.status, 200);

        // A controller without a configured socket never reports ready.
        let bare = test_controller(dir.path().join("bare"));
        assert_eq!(readyz(&bare).await.status, 503);
    }

    #[test]
    fn snapshot_records_reads_store() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        controller
            .store
            .create(
                "active",
                None,
                SnapshotKind::Active,
                "fusedev",
                None,
                &HashMap::new(),
            )
            .unwrap();

        let records = controller.snapshot_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key, "active");
    }

    #[compio::test]
    async fn cache_usage_and_gc_use_configured_cache_root() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        std::fs::create_dir_all(controller.cache.root()).unwrap();
        std::fs::write(controller.cache.root().join("old.blob.data"), b"data").unwrap();

        assert_eq!(controller.cache_usage().unwrap().total_files, 1);
        let report = controller
            .cache_gc_with_policy(&CacheGcPolicy {
                max_age: Some(Duration::from_secs(0)),
                ..CacheGcPolicy::default()
            })
            .await
            .unwrap();
        assert_eq!(report.removed_files, 1);
        assert_eq!(controller.cache_usage().unwrap().total_files, 0);
    }

    #[compio::test]
    async fn route_daemons_returns_json_array() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/daemons".to_string(),
                body: Vec::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body, serde_json::json!([]));
    }

    #[compio::test]
    async fn route_daemon_records_and_detail_return_persisted_records() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let record = DaemonStatusRecord {
            image_ref: "registry.local/team/app:1".to_string(),
            slug: "abc-app".to_string(),
            mountpoint: dir.path().join("daemons/abc-app/mnt"),
            bootstrap: dir.path().join("snapshots/base/fs/image/image.boot"),
            refcount: 0,
            holders: 0,
            state: "STOPPED".to_string(),
            live: false,
            updated_at: 1,
            pid: 0,
        };
        let records_dir = controller.supervisor.daemons_root().join("records");
        std::fs::create_dir_all(&records_dir).unwrap();
        std::fs::write(
            records_dir.join("abc-app.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();

        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/daemons/records".to_string(),
                body: Vec::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body[0]["slug"], "abc-app");

        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/daemons/abc-app/backend".to_string(),
                body: Vec::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["backend"], "registry");
        assert_eq!(body["slug"], "abc-app");
    }

    #[compio::test]
    async fn route_upgrade_reports_no_daemons_when_empty() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "POST".to_string(),
                path: "/api/v1/daemons/upgrade".to_string(),
                body: Vec::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["status"], "no_daemons");
        assert_eq!(body["report"]["attempted"], 0);
        assert_eq!(body["report"]["records"], serde_json::json!([]));
    }

    #[compio::test]
    async fn route_spawn_rejects_missing_bootstrap() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let body = serde_json::to_vec(&serde_json::json!({
            "image_ref": "registry.local/team/app:1",
            "bootstrap": dir.path().join("missing.boot"),
        }))
        .unwrap();
        let response = route_request(
            &controller,
            HttpRequest {
                method: "POST".to_string(),
                path: "/api/v1/daemons".to_string(),
                body,
            },
        )
        .await;

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["error"].as_str().unwrap().contains("is missing"));
    }

    #[compio::test]
    async fn route_cache_usage_reports_files() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        std::fs::create_dir_all(controller.cache.root()).unwrap();
        std::fs::write(controller.cache.root().join("item.blob.data"), b"data").unwrap();

        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/cache/usage".to_string(),
                body: Vec::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["total_files"], 1);
        assert_eq!(body["total_bytes"], 4);
        assert_eq!(body["entries"][0]["kind"], "blob_data");
    }

    #[compio::test]
    async fn route_cache_gc_accepts_policy_override() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        std::fs::create_dir_all(controller.cache.root()).unwrap();
        let file = controller.cache.root().join("item.blob.data");
        std::fs::write(&file, b"data").unwrap();

        let response = route_request(
            &controller,
            HttpRequest {
                method: "POST".to_string(),
                path: "/api/v1/cache/gc".to_string(),
                body: br#"{"max_age":"0s","dry_run":true}"#.to_vec(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(file.exists(), "dry-run GC must not delete the file");
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["removed_files"], 1);
        assert_eq!(body["removals"][0]["dry_run"], true);
    }

    #[compio::test]
    async fn route_prefetch_put_and_get_round_trip() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "PUT".to_string(),
                path: "/api/v1/prefetch".to_string(),
                body:
                    br#"[{"image":"registry.local/app:1","prefetch":"/bin/app\n/lib/libc.so\n"}]"#
                        .to_vec(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["images"], 1);

        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/prefetch".to_string(),
                body: Vec::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["registry.local/app:1"][0], "/bin/app");
        assert_eq!(body["registry.local/app:1"][1], "/lib/libc.so");
    }

    #[compio::test]
    async fn route_prefetch_profile_put_uses_structured_profile() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "PUT".to_string(),
                path: "/api/v1/prefetch/profile".to_string(),
                body: br#"{
                    "version":1,
                    "image":"registry.local/app:profile",
                    "files":[
                        {"path":"/bin/app","first_seen_unix":1,"hits":1},
                        {"path":"/lib//libc.so","first_seen_unix":2,"hits":1}
                    ]
                }"#
                .to_vec(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert_eq!(controller.profile_store.list().unwrap().len(), 1);

        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/prefetch".to_string(),
                body: Vec::new(),
            },
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            body["registry.local/app:profile"],
            serde_json::json!(["/bin/app", "/lib/libc.so"])
        );
    }

    #[compio::test]
    async fn route_auth_put_and_get_round_trip_without_secret_leak() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "PUT".to_string(),
                path: "/api/v1/auth".to_string(),
                body: br#"[{"registry":"registry.auth.local","auth":"dXNlcjpwYXNz","expires_in_seconds":60}]"#.to_vec(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["registries"].as_u64().unwrap() >= 1);

        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/auth".to_string(),
                body: Vec::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.as_array().unwrap().iter().any(|entry| {
            entry["registry"] == "registry.auth.local" && entry.get("auth").is_none()
        }));
    }

    #[compio::test]
    async fn route_unknown_endpoint_returns_404() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/missing".to_string(),
                body: Vec::new(),
            },
        )
        .await;

        assert_eq!(response.status, 404);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["error"].as_str().unwrap().contains("unknown endpoint"));
    }

    #[compio::test]
    async fn route_metrics_returns_prometheus_text() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        controller
            .store
            .create(
                "active",
                None,
                SnapshotKind::Active,
                "fusedev",
                None,
                &HashMap::new(),
            )
            .unwrap();
        std::fs::create_dir_all(controller.cache.root()).unwrap();
        std::fs::write(controller.cache.root().join("item.blob.data"), b"data").unwrap();
        controller
            .cache_gc_with_policy(&CacheGcPolicy {
                max_age: Some(Duration::from_secs(0)),
                dry_run: true,
                ..CacheGcPolicy::default()
            })
            .await
            .unwrap();

        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/metrics".to_string(),
                body: Vec::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "text/plain; version=0.0.4");
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("nydus_snapshotter_daemons 0"));
        assert!(body.contains("nydus_snapshotter_daemon_spawn_runs_total 0"));
        assert!(body.contains("nydus_snapshotter_daemon_upgrade_runs_total 0"));
        assert!(body.contains("nydus_snapshotter_snapshots 1"));
        assert!(body.contains("nydus_snapshotter_snapshots_by_kind{kind=\"active\"} 1"));
        assert!(body.contains("nydus_snapshotter_cache_bytes 4"));
        assert!(body.contains("nydus_snapshotter_cache_files 1"));
        assert!(body.contains("nydus_snapshotter_cache_artifact_bytes{kind=\"blob_data\"} 4"));
        assert!(body.contains("nydus_snapshotter_cache_artifact_files{kind=\"blob_data\"} 1"));
        assert!(body.contains("nydus_snapshotter_cache_gc_runs_total 1"));
        // The GC above was a DRY RUN — it deleted nothing, so the "removed"
        // counters must stay at 0 (they feed reclaimed-space alerting).
        assert!(body.contains("nydus_snapshotter_cache_gc_removed_files_total 0"));
        assert!(body.contains("nydus_snapshotter_cache_gc_removed_bytes_total 0"));
        assert!(body.contains("nydus_snapshotter_cache_gc_failures_total 0"));
        assert!(body.contains("nydusd_counts{version=\"in-process\"} 0"));
        assert!(body.contains("nydusd_lifetime_event_counts{event=\"spawn\"} 0"));
        assert!(body.contains("snapshotter_snapshot_operation_elapsed_milliseconds"));
        assert!(body.contains("snapshotter_cache_usage_kilobytes 0"));
        assert!(body.contains("snapshotter_run_time_seconds"));
    }

    #[test]
    fn prometheus_label_values_are_escaped() {
        assert_eq!(escape_label_value("plain"), "plain");
        assert_eq!(
            escape_label_value("quote\"slash\\line\n"),
            "quote\\\"slash\\\\line\\n"
        );
    }

    #[compio::test]
    async fn route_access_tracer_start_without_tracer_reports_not_applied() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "POST".to_string(),
                path: "/api/v1/access-tracer/start".to_string(),
                body: br#"{"image":"registry.local/app:1"}"#.to_vec(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["image"], "registry.local/app:1");
        assert_eq!(body["applied"], false);
        assert_eq!(body["mounts"], 0);
    }

    #[compio::test]
    async fn route_access_tracer_settle_without_tracer_reports_not_flushed() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "POST".to_string(),
                path: "/api/v1/access-tracer/settle".to_string(),
                body: br#"{"image":"registry.local/app:1"}"#.to_vec(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["image"], "registry.local/app:1");
        assert_eq!(body["applied"], false);
        assert_eq!(body["flushed"], false);
    }

    #[compio::test]
    async fn route_access_tracer_rejects_missing_image() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "POST".to_string(),
                path: "/api/v1/access-tracer/start".to_string(),
                body: br#"{"image":""}"#.to_vec(),
            },
        )
        .await;
        assert_eq!(response.status, 400);
    }

    /// `find_rootfs_in_mountinfo` cross-namespaces mountinfo strings to
    /// the host-side overlay rootfs mount-point. This is the exact bug
    /// commit 9e85c5cf fixed (`canonicalize("/proc/<pid>/root")`
    /// returned "/" and the snapshotter mark'd the host root fs); the
    /// extra `lowerdir=` tiebreaker added in this round prevents marking
    /// a SIBLING container's rootfs when two pods of the same image
    /// share an st_dev.
    #[test]
    fn find_rootfs_in_mountinfo_resolves_host_overlay_for_container() {
        let container = "\
3039 2510 0:274 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/.../snapshots/L/fs,upperdir=/U/fs,workdir=/U/work\n";
        let host = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
2460 30 0:274 / /run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/CID/rootfs rw,relatime shared:1614 - overlay overlay rw,lowerdir=/var/lib/.../snapshots/L/fs,upperdir=/U/fs,workdir=/U/work\n";
        let p = find_rootfs_in_mountinfo(container, host).unwrap();
        assert_eq!(
            p.to_str().unwrap(),
            "/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/CID/rootfs"
        );
    }

    #[test]
    fn find_rootfs_in_mountinfo_disambiguates_siblings_via_lowerdir() {
        // Two host-side overlay mounts on the same st_dev (0:274) — only
        // the second matches the container's lowerdir. Without the
        // tiebreaker the helper would return the first one.
        let container = "\
3039 2510 0:274 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/.../snapshots/WANT/fs,upperdir=/U/fs,workdir=/U/work\n";
        let host = "\
2459 30 0:274 / /run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/OTHER/rootfs rw - overlay overlay rw,lowerdir=/var/lib/.../snapshots/SIBLING/fs,upperdir=/V/fs,workdir=/V/work\n\
2460 30 0:274 / /run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/CID/rootfs rw - overlay overlay rw,lowerdir=/var/lib/.../snapshots/WANT/fs,upperdir=/U/fs,workdir=/U/work\n";
        let p = find_rootfs_in_mountinfo(container, host).unwrap();
        assert!(
            p.to_str().unwrap().ends_with("k8s.io/CID/rootfs"),
            "expected the CID rootfs (matching lowerdir), got {}",
            p.display()
        );
    }

    #[test]
    fn find_rootfs_in_mountinfo_errors_when_no_host_mount_matches() {
        let container = "\
3039 2510 0:274 / / rw - overlay overlay rw,lowerdir=/L/fs\n";
        let host = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        assert!(find_rootfs_in_mountinfo(container, host).is_err());
    }

    #[test]
    fn find_rootfs_in_mountinfo_does_not_match_host_root_fs() {
        // st_dev matches but mount-point is "/" not the runtime rootfs
        // path. The earlier version that canonicalised
        // `/proc/<pid>/root` returned "/" and silently marked the host
        // root fs; this assertion locks in that we won't regress.
        let container = "\
3039 2510 0:1 / / rw - overlay overlay rw,lowerdir=/L\n";
        let host = "\
1 0 0:1 / / rw - overlay overlay rw,lowerdir=/L\n";
        assert!(find_rootfs_in_mountinfo(container, host).is_err());
    }

    #[test]
    fn extract_lowerdir_pulls_value_out_of_super_options() {
        let line = "2460 30 0:274 / /R rw - overlay overlay rw,lowerdir=/A/fs,upperdir=/B/fs,workdir=/C/fs,uuid=on";
        assert_eq!(extract_lowerdir(line).as_deref(), Some("/A/fs"));
    }

    #[test]
    fn extract_lowerdir_is_none_for_non_overlay() {
        let line = "1 0 8:1 / / rw - ext4 /dev/sda1 rw";
        assert!(extract_lowerdir(line).is_none());
    }

    #[compio::test]
    async fn route_debug_allocator_returns_parseable_stats() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let response = route_request(
            &controller,
            HttpRequest {
                method: "GET".to_string(),
                path: "/debug/allocator".to_string(),
                body: Vec::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "application/json");
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        // The numeric fields are platform-dependent (populated on Linux via
        // /proc/self/status, absent elsewhere), but the shape and the
        // "what did we actually read" fields must always be present.
        assert!(body["source"].is_string());
        assert_eq!(body["mimalloc_extended_stats_available"], false);
        assert!(body["note"].is_string());
        assert!(body.get("current_rss_bytes").is_some());
        assert!(body.get("peak_rss_bytes").is_some());
        assert!(body.get("virtual_size_bytes").is_some());

        #[cfg(target_os = "linux")]
        {
            assert_eq!(body["source"], "proc_self_status");
            assert!(
                body["current_rss_bytes"].as_u64().unwrap() > 0,
                "a live process should report nonzero RSS on Linux"
            );
        }
    }

    #[test]
    fn parse_proc_status_memory_reads_rss_hwm_and_vsize() {
        let status = "\
Name:\ttest\n\
VmPeak:\t   10240 kB\n\
VmSize:\t    8192 kB\n\
VmHWM:\t     4096 kB\n\
VmRSS:\t     2048 kB\n\
Threads:\t4\n";
        let (current, peak, virt) = parse_proc_status_memory(status);
        assert_eq!(current, Some(2048 * 1024));
        assert_eq!(peak, Some(4096 * 1024));
        assert_eq!(virt, Some(8192 * 1024));
    }

    #[test]
    fn parse_proc_status_memory_is_none_for_missing_fields() {
        let status = "Name:\ttest\nThreads:\t1\n";
        assert_eq!(parse_proc_status_memory(status), (None, None, None));
    }

    #[test]
    fn parse_status_kb_field_parses_leading_integer() {
        assert_eq!(parse_status_kb_field("   2048 kB"), Some(2048 * 1024));
        assert_eq!(parse_status_kb_field("   not-a-number kB"), None);
    }
}
