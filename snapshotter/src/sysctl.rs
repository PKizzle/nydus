// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! System-controller backend operations.
//!
//! The Go snapshotter exposed these capabilities through an HTTP API.  The
//! Rust implementation keeps the transport separate from the control plane so
//! a Unix-socket REST server, tests, or future gRPC admin service can all call
//! the same operations.

use crate::auto_zran::AutoZranManager;
use crate::cache::{CacheArtifactKind, CacheGcPolicy, CacheGcReport, CacheManager, CacheUsage};
use crate::daemon::auth::{runtime_auth_records, set_runtime_auth, RuntimeAuthRequest};
use crate::daemon::{
    DaemonStatusRecord, DaemonSupervisor, DaemonUpgradeOptions, DaemonUpgradeReport,
};
use crate::metrics::{CacheMetricSnapshot, SnapshotterMetrics};
use crate::prefetch_profile::{
    normalize_prefetch_files, runtime_prefetch_records, set_runtime_prefetch, PrefetchProfile,
    PrefetchProfileStore,
};
use crate::store::{SnapshotInfo, SnapshotStore};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

const MAX_HEADER_BYTES: usize = 16 * 1024;
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
    metrics: Arc<ControllerMetrics>,
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

    fn record_cache_gc(&self, report: &CacheGcReport) {
        self.cache_gc_runs_total.fetch_add(1, Ordering::Relaxed);
        self.cache_gc_removed_files_total
            .fetch_add(usize_to_u64(report.removed_files), Ordering::Relaxed);
        self.cache_gc_removed_bytes_total
            .fetch_add(report.removed_bytes, Ordering::Relaxed);
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

impl SystemController {
    pub fn new(
        supervisor: Arc<DaemonSupervisor>,
        store: Arc<SnapshotStore>,
        cache: CacheManager,
        cache_policy: CacheGcPolicy,
    ) -> Self {
        Self::new_with_metrics(
            supervisor,
            store,
            cache,
            cache_policy,
            Arc::new(SnapshotterMetrics::new()),
        )
    }

    pub fn new_with_metrics(
        supervisor: Arc<DaemonSupervisor>,
        store: Arc<SnapshotStore>,
        cache: CacheManager,
        cache_policy: CacheGcPolicy,
        snapshotter_metrics: Arc<SnapshotterMetrics>,
    ) -> Self {
        Self::new_with_metrics_and_auto_zran(
            supervisor,
            store,
            cache,
            cache_policy,
            snapshotter_metrics,
            None,
        )
    }

    pub fn new_with_metrics_and_auto_zran(
        supervisor: Arc<DaemonSupervisor>,
        store: Arc<SnapshotStore>,
        cache: CacheManager,
        cache_policy: CacheGcPolicy,
        snapshotter_metrics: Arc<SnapshotterMetrics>,
        auto_zran: Option<Arc<AutoZranManager>>,
    ) -> Self {
        let profile_store = PrefetchProfileStore::from_cache_root(cache.root());
        if let Err(e) = profile_store.restore_runtime() {
            warn!(error = %e, "failed to restore persisted prefetch profiles");
        }
        Self {
            supervisor,
            store,
            cache,
            cache_policy,
            profile_store,
            snapshotter_metrics,
            auto_zran,
            metrics: Arc::new(ControllerMetrics::default()),
        }
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

    /// Checkpoint live daemon records. This is the first safe sysctl upgrade
    /// hook; real FD handoff can build on the persisted record format.
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
    pub fn cache_gc(&self) -> Result<CacheGcReport> {
        let report = self.cache.garbage_collect(&self.cache_policy)?;
        self.metrics.record_cache_gc(&report);
        Ok(report)
    }

    /// Trigger cache GC with a one-shot policy override. Useful for a future
    /// `/api/v1/daemons/{id}/cache/gc` request body without mutating global
    /// config.
    pub fn cache_gc_with_policy(&self, policy: &CacheGcPolicy) -> Result<CacheGcReport> {
        let report = self.cache.garbage_collect(policy)?;
        self.metrics.record_cache_gc(&report);
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
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to remove stale sysctl socket {}", path.display()))?;
    }
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("failed to bind sysctl socket {}", path.display()))?;
    info!(path = %path.display(), "starting nydus system-controller API");

    loop {
        let (stream, _) = listener.accept().await?;
        let controller = controller.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, controller).await {
                warn!(error = %e, "sysctl connection failed");
            }
        });
    }
}

async fn handle_connection(mut stream: UnixStream, controller: SystemController) -> Result<()> {
    let request = read_request(&mut stream).await?;
    let response = route_request(&controller, request).await;
    stream.write_all(&response.to_http()).await?;
    stream.shutdown().await?;
    Ok(())
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
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn to_http(&self) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        )
        .into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

async fn read_request(stream: &mut UnixStream) -> Result<HttpRequest> {
    let mut buf = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            bail!("HTTP headers exceed {MAX_HEADER_BYTES} bytes");
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("client closed connection before completing HTTP request");
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_bytes = &buf[..header_end];
    let headers = std::str::from_utf8(header_bytes).context("HTTP headers are not UTF-8")?;
    let mut lines = headers.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("missing HTTP method")?.to_string();
    let path = parts.next().context("missing HTTP path")?.to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .context("invalid content-length")?;
            }
        }
    }
    if content_length > MAX_BODY_BYTES {
        bail!("HTTP body exceeds {MAX_BODY_BYTES} bytes");
    }

    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("client closed connection before completing HTTP body");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = buf[body_start..body_start + content_length].to_vec();

    debug!(%method, %path, body_bytes = body.len(), "sysctl request received");
    Ok(HttpRequest { method, path, body })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
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
        ("POST", "/api/v1/cache/gc") => handle_cache_gc(controller, &request.body),
        ("GET", "/api/v1/prefetch") => match controller.prefetch_entries() {
            Ok(entries) => json_response(200, entries),
            Err(e) => error_response(500, e.to_string()),
        },
        ("PUT", "/api/v1/prefetch") => handle_prefetch_put(controller, &request.body),
        ("PUT", "/api/v1/prefetch/profile") => {
            handle_prefetch_profile_put(controller, &request.body)
        }
        ("GET", "/api/v1/auth") => match runtime_auth_records() {
            Ok(records) => json_response(200, records),
            Err(e) => error_response(500, e.to_string()),
        },
        ("PUT", "/api/v1/auth") => handle_auth_put(&request.body),
        ("GET", "/metrics") => metrics_response(controller).await,
        _ => route_dynamic_request(controller, &request.method, path, &request.body).await,
    }
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

async fn route_dynamic_request(
    controller: &SystemController,
    method: &str,
    path: &str,
    body: &[u8],
) -> HttpResponse {
    if let Some(id) = path.strip_prefix("/api/v1/daemons/") {
        if let Some((id, suffix)) = id.split_once('/') {
            if method == "POST" && suffix == "cache/gc" {
                return handle_cache_gc(controller, body);
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

fn handle_cache_gc(controller: &SystemController, body: &[u8]) -> HttpResponse {
    let result = if body.is_empty() {
        controller.cache_gc()
    } else {
        let req = match serde_json::from_slice::<CacheGcRequest>(body) {
            Ok(req) => req,
            Err(e) => return error_response(400, format!("invalid cache GC request: {e}")),
        };
        let policy = match req.into_policy() {
            Ok(policy) => policy,
            Err(e) => return error_response(400, e.to_string()),
        };
        controller.cache_gc_with_policy(&policy)
    };

    match result {
        Ok(report) => json_response(200, CacheGcReportResponse::from(report)),
        Err(e) => error_response(500, e.to_string()),
    }
}

fn json_response<T: Serialize>(status: u16, body: T) -> HttpResponse {
    match serde_json::to_vec(&body) {
        Ok(body) => HttpResponse {
            status,
            reason: reason_phrase(status),
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
        reason: reason_phrase(status),
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

    let blob_data_files = cache_artifacts
        .get("blob_data")
        .map(|(files, _bytes)| *files)
        .unwrap_or_default();
    body.push_str(
        &controller
            .snapshotter_metrics
            .render_prometheus(CacheMetricSnapshot {
                total_bytes: cache.total_bytes,
                deleted_blobs: metrics.cache_gc_removed_files_total,
                deletion_errors: metrics.cache_gc_failures_total,
                blobs_in_use: blob_data_files,
            }),
    );

    HttpResponse {
        status: 200,
        reason: reason_phrase(200),
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

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
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

    #[tokio::test]
    async fn list_daemons_is_empty_for_new_controller() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        assert!(controller.list_daemons().await.is_empty());
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

    #[test]
    fn cache_usage_and_gc_use_configured_cache_root() {
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
            .unwrap();
        assert_eq!(report.removed_files, 1);
        assert_eq!(controller.cache_usage().unwrap().total_files, 0);
    }

    #[tokio::test]
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

    #[tokio::test]
    async fn route_daemon_records_and_detail_return_persisted_records() {
        let dir = tempdir().unwrap();
        let controller = test_controller(dir.path().to_path_buf());
        let record = DaemonStatusRecord {
            image_ref: "registry.local/team/app:1".to_string(),
            slug: "abc-app".to_string(),
            mountpoint: dir.path().join("daemons/abc-app/mnt"),
            bootstrap: dir.path().join("snapshots/base/fs/image/image.boot"),
            refcount: 0,
            state: "STOPPED".to_string(),
            live: false,
            updated_at: 1,
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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
        assert!(body.contains("nydus_snapshotter_cache_gc_removed_files_total 1"));
        assert!(body.contains("nydus_snapshotter_cache_gc_removed_bytes_total 4"));
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
}
