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

/// How old an auto-zran per-job scratch directory's mtime must be before the
/// reconciler treats it as abandoned and removes it. A successful BASE stage
/// deliberately RETAINS its job dir (plus `artifact.json`) so the optimize
/// stage can reuse the create+merge output; only a completed OPTIMIZE stage
/// removes the dir (`auto_zran::cleanup_work_dir`). This sweep is the fallback
/// for jobs whose settle never arrives (pod died pre-settle, worker crashed
/// mid-conversion). Sweeping a retained base dir is safe: a late optimize job
/// simply finds no reusable base (`auto_zran::load_reusable_base_artifact` →
/// `None`) and degrades to the full pipeline. Six hours is deliberately
/// generous: conversions run at idle scheduling priority and a large
/// multi-layer image can legitimately churn for a long time, so the sweep must
/// never race a slow-but-healthy job (the live job is additionally excluded
/// via `active_job_key()`).
const AUTO_ZRAN_STALE_JOB_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(6 * 60 * 60);

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

    fn invalid_argument(message: impl Into<String>) -> Self {
        Self(Box::new(snapshots::tonic::Status::invalid_argument(
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

/// Convert a store `SnapshotInfo` to the containerd `Info` type.
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

/// How `update()` should apply the label field of an incoming `Info`, derived
/// from containerd's protobuf `update_mask`.
///
/// containerd sends a field-mask whose paths select which mutable properties of
/// a snapshot to write. For snapshots only labels are mutable, so exactly two
/// shapes are recognised (mirroring containerd's own `metadata` snapshotter):
///   * a bare `labels` path — replace the entire label set;
///   * `labels.<key>` paths — merge only those keys, preserving every other
///     existing label (crucially containerd's `containerd.io/gc.ref.*` GC roots).
#[derive(Debug, PartialEq, Eq)]
enum LabelMask {
    /// Replace all labels with the incoming set (also the `fieldpaths == None`
    /// default).
    ReplaceAll,
    /// Merge only these keys from the incoming set into the existing labels.
    Merge(Vec<String>),
}

/// Parse containerd `update_mask` paths into a [`LabelMask`].
///
/// Returns `Err(path)` for the first path that is neither `labels` nor
/// `labels.<key>` so the caller can answer with gRPC `InvalidArgument`, matching
/// containerd's own snapshotter (`cannot update %q field`). A bare `labels`
/// anywhere in the list wins (replace-all subsumes any per-key merge, exactly as
/// containerd's sequential apply would end up), but every path is still validated
/// so an unsupported field is never silently accepted.
fn parse_label_mask(fieldpaths: &[String]) -> Result<LabelMask, String> {
    let mut keys = Vec::new();
    let mut replace_all = false;
    for path in fieldpaths {
        if path == "labels" {
            replace_all = true;
        } else if let Some(key) = path.strip_prefix("labels.") {
            keys.push(key.to_string());
        } else {
            return Err(path.clone());
        }
    }
    Ok(if replace_all {
        LabelMask::ReplaceAll
    } else {
        LabelMask::Merge(keys)
    })
}

/// Merge the masked `keys` from `incoming` onto a clone of `existing`, preserving
/// all other existing labels. An absent key in `incoming` is written as the empty
/// string, matching containerd's `updated.Labels[key] = info.Labels[key]` (a Go
/// map miss yields "").
fn merge_labels(
    existing: &HashMap<String, String>,
    incoming: &HashMap<String, String>,
    keys: &[String],
) -> HashMap<String, String> {
    let mut merged = existing.clone();
    for key in keys {
        merged.insert(key.clone(), incoming.get(key).cloned().unwrap_or_default());
    }
    merged
}

/// A single `field==value` term of a containerd Walk filter.
#[derive(Debug, PartialEq, Eq)]
enum FilterTerm {
    /// `name==` / `key==` — the snapshot key.
    Name(String),
    /// `parent==` — the parent key ("" when the snapshot has no parent).
    Parent(String),
    /// `kind==` — one of `active` / `committed` / `view`.
    Kind(String),
    /// `labels."<key>"==<value>` — a specific label's value.
    Label { key: String, value: String },
}

/// Strip one pair of surrounding double quotes, if present. containerd's filter
/// grammar allows both quoted and bare values/keys (`labels."k"==v`, `key==v`,
/// `key=="v"`).
fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Parse a single `field==value` term. Returns `None` for any unsupported field
/// or operator so the whole filter falls back to unfiltered.
fn parse_filter_term(term: &str) -> Option<FilterTerm> {
    let (field, value) = term.trim().split_once("==")?;
    let field = field.trim();
    let value = unquote(value).to_string();
    if let Some(rest) = field.strip_prefix("labels.") {
        let key = unquote(rest).to_string();
        if key.is_empty() {
            return None;
        }
        return Some(FilterTerm::Label { key, value });
    }
    match field {
        "name" | "key" => Some(FilterTerm::Name(value)),
        "parent" => Some(FilterTerm::Parent(value)),
        "kind" => Some(FilterTerm::Kind(value)),
        _ => None,
    }
}

/// Parse one comma-separated filter string into a conjunction (AND) of terms.
/// An empty string is a valid filter that matches everything (empty conjunction).
/// Returns `None` if any term is unsupported.
fn parse_filter_expr(s: &str) -> Option<Vec<FilterTerm>> {
    let mut terms = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        terms.push(parse_filter_term(part)?);
    }
    Some(terms)
}

/// Parse the containerd Walk `filters` vec into a disjunction (OR) of
/// conjunctions (AND). Returns `None` if ANY filter string is unsupported, so the
/// caller can safely fall back to the unfiltered list (containerd/ctr post-filter
/// the stream anyway).
fn parse_filters(filters: &[String]) -> Option<Vec<Vec<FilterTerm>>> {
    filters.iter().map(|f| parse_filter_expr(f)).collect()
}

/// Map a stored snapshot kind (`kind_active` etc.) to the containerd filter
/// token (`active` etc.). Routes through [`SnapshotKind::from_store_str`] so the
/// store's on-disk kind strings stay the single source of truth — if they ever
/// change, this mapping follows rather than silently stopping to match.
fn kind_filter_token(store_kind: &str) -> &'static str {
    match crate::store::SnapshotKind::from_store_str(store_kind) {
        Ok(crate::store::SnapshotKind::Active) => "active",
        Ok(crate::store::SnapshotKind::Committed) => "committed",
        Ok(crate::store::SnapshotKind::View) => "view",
        Err(_) => "unknown",
    }
}

fn term_matches(term: &FilterTerm, info: &SnapshotInfo) -> bool {
    match term {
        FilterTerm::Name(v) => info.key == *v,
        FilterTerm::Parent(v) => info.parent.as_deref().unwrap_or("") == v,
        FilterTerm::Kind(v) => kind_filter_token(&info.kind) == v,
        FilterTerm::Label { key, value } => info.labels.get(key).is_some_and(|x| x == value),
    }
}

/// A snapshot matches when it satisfies ALL terms of ANY filter expression
/// (OR-of-ANDs). An empty expression list means no filter was supplied → match
/// everything.
fn snapshot_matches(info: &SnapshotInfo, exprs: &[Vec<FilterTerm>]) -> bool {
    if exprs.is_empty() {
        return true;
    }
    exprs
        .iter()
        .any(|terms| terms.iter().all(|t| term_matches(t, info)))
}

fn snapshot_status_label<T>(result: &Result<T, SnapshotterError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(error) => error.status_label(),
    }
}

/// Parse `lowerdir=…` out of the first overlay mount in `mounts`, returning
/// **every** layer directory in the list. Used by the access tracer, which
/// must register each lowerdir as an attribution root: while a single
/// `FAN_MARK_MOUNT` mark covers event *delivery* for the whole host mount,
/// the tracer attributes an event to an image by mount-root *prefix* — an
/// open that resolves into a sibling layer's `…/snapshots/<other>/fs/…`
/// directory matches no registered root and is dropped, so registering only
/// lowerdir[0] systematically truncated multi-layer images' profiles.
///
/// containerd overlay mounts encode the layer stack as
/// `lowerdir=L0:L1:…:Ln,upperdir=U,workdir=W`, where `L0` is the layer
/// closest to the rootfs read order. The writable upper is deliberately not
/// included — it has nothing to do with the image's access pattern.
fn all_lowerdirs(mounts: &[snapshots::api::types::Mount]) -> Vec<PathBuf> {
    for mount in mounts {
        if mount.r#type != "overlay" {
            continue;
        }
        for opt in &mount.options {
            if let Some(rest) = opt.strip_prefix("lowerdir=") {
                return rest
                    .split(':')
                    .filter(|dir| !dir.is_empty())
                    .map(PathBuf::from)
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Resolve a per-image fs-driver override from a Prepare's labels, if the
/// `containerd.io/snapshot/nydus-fs-driver` label names a known driver.
fn driver_override_from_labels(
    labels: &HashMap<String, String>,
) -> Option<crate::config::FsDriverType> {
    labels
        .get(crate::source::labels::NYDUS_FS_DRIVER)
        .and_then(|hint| crate::config::FsDriverType::from_hint(hint))
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

/// The main snapshotter implementation.
///
/// Bridges containerd's gRPC proxy-plugin protocol to the overlay engine
/// and daemon supervisor.
pub struct NydusSnapshotter {
    /// Snapshotter runtime config. Held so `prepare()` can read feature flags
    /// (e.g. `features.referrer_detect`) and pass the config to the referrer
    /// detector for registry auth/timeout.
    config: SnapshotterConfig,
    store: Arc<SnapshotStore>,
    overlay: OverlayEngine,
    supervisor: Arc<DaemonSupervisor>,
    metrics: Arc<SnapshotterMetrics>,
    /// The reconciler, shared with the background reconciliation loop. The
    /// Cleanup RPC (`clear()`) runs a single synchronous pass through it for
    /// on-demand orphan reclamation.
    reconciler: Arc<Reconciler>,
    /// Auto-accel access tracer. Disabled (no-op) when
    /// `auto_zran.capture.enable = false` or fanotify init fails; cheap
    /// (no-op) clone otherwise.
    access_tracer: Arc<crate::access_tracer::AccessTracer>,
    /// Conversion-queue manager. `Some` when `auto_zran.enable` is on. Used by
    /// `prepare` to enqueue the stage-1 BASE conversion the moment an image
    /// becomes eligible, so peers can fetch a sidecar long before this pod's
    /// access tracer settles (which drives stage 2). Non-blocking channel push.
    auto_zran: Option<Arc<AutoZranManager>>,
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
    ///
    /// `holder` is the snapshot key on whose behalf the daemon is resolved; the
    /// supervisor registers it idempotently, so repeated `Mounts` RPCs for a
    /// key cannot inflate the daemon refcount.
    async fn resolve_nydus_mount(
        &self,
        parent: &str,
        call_labels: &HashMap<String, String>,
        holder: &str,
    ) -> Result<Option<(NydusMetaInfo, PathBuf)>, SnapshotterError> {
        let store = self.store.as_ref();
        let meta = self
            .overlay
            .nydus_meta_info(store, parent, call_labels)
            .map_err(|e| SnapshotterError::internal(e.to_string()))?;
        let Some(meta) = meta else {
            return Ok(None);
        };
        // Per-image driver override from the `nydus-fs-driver` label (e.g.
        // `tarfs`) supplied on this RPC's call labels.
        let driver_override = driver_override_from_labels(call_labels);
        let handle = self
            .supervisor
            .ensure_instance(&meta.image_ref, &meta.bootstrap, holder, driver_override)
            .await
            .map_err(|e| {
                warn!(image_ref = %meta.image_ref, error = %e, "failed to start nydus daemon");
                SnapshotterError::internal(e.to_string())
            })?;
        let mountpoint = handle.mountpoint().to_path_buf();
        Ok(Some((meta, mountpoint)))
    }

    /// Stamp `image_ref` into the [`labels::NYDUS_DAEMON_IMAGE_REF`] label of
    /// snapshot `key`, so `remove(key)` can release the daemon reference the
    /// key acquired. Best-effort: on failure the daemon stays referenced and a
    /// warning is logged.
    fn stamp_daemon_ref_label(&self, key: &str, image_ref: &str) {
        use crate::source::labels::NYDUS_DAEMON_IMAGE_REF;
        let store = self.store.as_ref();
        let merged = store.stat(key).map(|info| {
            let mut labels: Vec<(String, String)> = info
                .labels
                .into_iter()
                .filter(|(k, _)| k != NYDUS_DAEMON_IMAGE_REF)
                .collect();
            labels.push((NYDUS_DAEMON_IMAGE_REF.to_string(), image_ref.to_string()));
            labels
        });
        let result = merged.and_then(|labels| store.update(key, &labels));
        if let Err(e) = result {
            warn!(
                key,
                image_ref,
                error = %e,
                "failed to stamp daemon-ref label; daemon release on remove() will miss this key"
            );
        }
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
        holder: &str,
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
            Ok(None) => {
                // No sidecar for this manifest. If the ref previously resolved
                // to different content (tag repoint), clear the per-ref
                // conversion dedupe + tracer skip so the new content gets
                // converted and captured instead of staying suppressed until a
                // snapshotter restart.
                if let Some(manager) = self.auto_zran.as_ref()
                    && manager.note_sidecar_missing(image_ref, &info.manifest_digest)
                {
                    self.access_tracer.clear_image_skip(image_ref);
                }
                return Ok(None);
            }
            Err(e) => {
                warn!(image_ref, error = %e, "auto-accel discovery failed; falling back to overlay");
                return Ok(None);
            }
        };
        // Daemon start failure is NON-FATAL: the sidecar mount is an
        // optimization, never a requirement. Failing the prepare would wedge
        // pods in CreateContainerError loops on hosts where the fanotify
        // daemon cannot come up; falling back to overlay keeps the pod
        // scheduling while the warn (with the full error chain) tells the
        // operator why acceleration is off.
        let handle = match self
            .supervisor
            .ensure_instance_local(image_ref, &staged.bootstrap, &staged.backend_dir, holder)
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
        fieldpaths: Option<Vec<String>>,
    ) -> Result<Info, Self::Error> {
        let timer = self.metrics.start_snapshot_operation("update");
        let result = async {
            info!(name = %info.name, fieldpaths = ?fieldpaths, labels = ?info.labels, "update snapshot");
            let store = self.store.as_ref();

            // Honor containerd's field-mask. Absent mask (`None`) replaces all
            // labels; a bare `labels` path does the same; `labels.<key>` paths
            // merge only those keys, preserving every other existing label so a
            // masked update never clobbers containerd's GC-root labels.
            let mask = match fieldpaths.as_deref() {
                None => LabelMask::ReplaceAll,
                Some(paths) => parse_label_mask(paths).map_err(|path| {
                    warn!(name = %info.name, %path, "update snapshot: unsupported fieldpath");
                    SnapshotterError::invalid_argument(format!(
                        "cannot update {path:?} field on snapshot {:?}",
                        info.name
                    ))
                })?,
            };

            // Stat up front on BOTH mask paths so a missing snapshot always
            // answers NotFound (containerd's expectation), not Internal — the
            // merge path needs the existing labels anyway, and the replace-all
            // path needs the existence check for a consistent status code.
            //
            // This stat + the store.update below is a read-then-write TOCTOU. It
            // is safe only because containerd serializes RPCs per snapshot key,
            // so no concurrent update can race between the two calls.
            let existing = store.stat(&info.name).map_err(|e| {
                warn!(name = %info.name, error = %e, "update snapshot: not found");
                SnapshotterError::not_found(e.to_string())
            })?;

            let new_labels = match mask {
                LabelMask::ReplaceAll => info.labels.clone(),
                LabelMask::Merge(keys) => merge_labels(&existing.labels, &info.labels, &keys),
            };

            let labels: Vec<(String, String)> = new_labels.into_iter().collect();
            store.update(&info.name, &labels).map_err(|e| {
                warn!(name = %info.name, error = %e, "update snapshot failed");
                SnapshotterError::internal(e.to_string())
            })?;
            // Re-fetch the updated info (with the bumped updated_at the store sets).
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
            // Full recursive stat walk of the snapshot tree — offload it so a
            // large snapshot cannot stall the shared gRPC reactor thread.
            let overlay = self.overlay.clone();
            let store = Arc::clone(&self.store);
            let walk_key = key.clone();
            let (size, inodes) = blocking::unblock(move || overlay.usage(&store, &walk_key))
                .await
                .map_err(|e| {
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

            if let Some((_, daemon_mnt)) = self.resolve_nydus_mount(&parent, &labels, &key).await? {
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
                    if let Some((_, daemon_mnt)) = self.resolve_nydus_mount(&parent, &labels, &key).await? {
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
                                // routing AND capture, and without the log
                                // there is no signal that the lookup
                                // pipeline itself is broken.
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
                        && let Some(daemon_mnt) =
                            self.resolve_auto_accel_mount(image_ref, &key).await?
                    {
                        debug!(key, parent, mountpoint = %daemon_mnt.display(), "prepared auto-accel rootfs");
                        // No nydus meta layer exists in this chain for remove()
                        // to find the daemon by — record it on the snapshot.
                        self.stamp_daemon_ref_label(&key, image_ref);
                        return Ok(self.rewrite_mounts_with_daemon(&key, &daemon_mnt, false));
                    }

                    // Referrer serving (default-off, opt-in). When
                    // `features.referrer_detect` is enabled, consult the OCI
                    // referrers API to see whether this image ref is a
                    // *published* nydus image (bootstrap distributed as a
                    // referrer artifact, the nydusify / Go-snapshotter model).
                    // On a NydusRafs hit we fetch + digest-verify the bootstrap
                    // (`materialize_bootstrap_blocking`) and mount the daemon
                    // via the shared `ensure_instance` path — the very same
                    // mount used by `resolve_nydus_mount` — then substitute the
                    // daemon mount for the overlay. nydusd's registry backend
                    // (built from `image_ref`) serves every data blob on demand
                    // from `/v2/<repo>/blobs/sha256:<blob_id>`, so the bootstrap
                    // is the only artifact materialized here.
                    //
                    // Like the auto-accel branch above, this is best-effort and
                    // NON-FATAL: every detection / auth / network / materialize
                    // / daemon-start error is swallowed and control falls through
                    // to the overlay / access-tracer path, so a pod is NEVER
                    // blocked on referrer serving. Runs off the gRPC runtime
                    // (cyper is `!Send`) via the `*_blocking` helpers; the
                    // module-global LRU caches both nydus hits and StandardOci
                    // misses, so detection costs at most one registry round-trip
                    // cluster-lifetime and the bootstrap is cached on disk.
                    if self.config.snapshotter.features.referrer_detect
                        && let Some(image_ref) = image_ref.as_deref()
                    {
                        use crate::source::referrer::ImageType;
                        match crate::source::referrer::detect_referrer_blocking(
                            image_ref,
                            &self.config,
                        )
                        .await
                        {
                            Ok(info) => match info.image_type {
                                ImageType::NydusRafs => {
                                    if let Some(bootstrap_digest) = info.bootstrap_digest.as_deref() {
                                        // `materialize_bootstrap_blocking` is
                                        // synchronous and blocks its thread on
                                        // the compio HTTP runtime; offload it
                                        // via `blocking::unblock` so the gRPC
                                        // reactor is never blocked and no
                                        // `block_on` nests inside the running
                                        // runtime (same model as
                                        // `detect_referrer_blocking`).
                                        let materialized = {
                                            let image_ref = image_ref.to_string();
                                            let bootstrap_digest = bootstrap_digest.to_string();
                                            let config = self.config.clone();
                                            let root = self.config.snapshotter.root.clone();
                                            blocking::unblock(move || {
                                                crate::source::referrer::materialize_bootstrap_blocking(
                                                    &image_ref,
                                                    &bootstrap_digest,
                                                    &config,
                                                    &root,
                                                )
                                            })
                                            .await
                                        };
                                        // A published nydus image may pin its
                                        // serving driver via the referrer's
                                        // `nydus-fs-driver` annotation (e.g. a
                                        // tarfs/dm-verity image).
                                        let driver_override = info
                                            .fs_driver_hint
                                            .as_deref()
                                            .and_then(crate::config::FsDriverType::from_hint);
                                        match materialized {
                                            Ok(bootstrap) => match self
                                                .supervisor
                                                .ensure_instance(image_ref, &bootstrap, &key, driver_override)
                                                .await
                                            {
                                                Ok(handle) => {
                                                    let mountpoint =
                                                        handle.mountpoint().to_path_buf();
                                                    info!(
                                                        image = %image_ref,
                                                        bootstrap = bootstrap_digest,
                                                        mountpoint = %mountpoint.display(),
                                                        "serving published nydus image via OCI referrers (B4b)"
                                                    );
                                                    // Like the auto-accel branch:
                                                    // no meta layer for remove()
                                                    // to find the daemon by.
                                                    self.stamp_daemon_ref_label(&key, image_ref);
                                                    return Ok(self.rewrite_mounts_with_daemon(
                                                        &key,
                                                        &mountpoint,
                                                        false,
                                                    ));
                                                }
                                                Err(e) => warn!(
                                                    image = %image_ref,
                                                    error = format!("{e:#}"),
                                                    "referrer nydus daemon failed to start; falling back to overlay"
                                                ),
                                            },
                                            Err(e) => warn!(
                                                image = %image_ref,
                                                bootstrap = bootstrap_digest,
                                                error = format!("{e:#}"),
                                                "failed to materialize referrer bootstrap; falling back to overlay"
                                            ),
                                        }
                                    } else {
                                        warn!(
                                            image = %image_ref,
                                            "published nydus image detected via OCI referrers but referrer carried no bootstrap digest; falling back to overlay"
                                        );
                                    }
                                }
                                ImageType::OciBlockDevice => info!(
                                    image = %image_ref,
                                    fs_driver_hint = info.fs_driver_hint.as_deref().unwrap_or("<none>"),
                                    "OCI block-device image detected via OCI referrers; serving not yet wired (see B4b)"
                                ),
                                ImageType::StandardOci => debug!(
                                    image = %image_ref,
                                    "referrer detection: standard OCI image (no nydus optimization)"
                                ),
                            },
                            Err(e) => debug!(
                                image = %image_ref,
                                error = %e,
                                "referrer detection failed; falling through to overlay"
                            ),
                        }
                    }

                    // Two-stage auto-accel, stage 1: no sidecar exists yet, so
                    // enqueue the BASE conversion immediately (empty prefetch →
                    // a fully servable sidecar). This is a non-blocking channel
                    // push; prepare NEVER awaits conversion and still returns the
                    // overlay mounts below. The worker uploads the base sidecar
                    // ASAP so peers requesting this image early can fetch it,
                    // instead of waiting the full pod-start + tracer-settle
                    // (5-60s) + convert window and hitting NotFound → overlay.
                    if let (Some(manager), Some(image_ref)) =
                        (self.auto_zran.as_ref(), image_ref.as_deref())
                    {
                        manager.try_enqueue_base(image_ref);
                    }

                    // Auto-accel capture (stage 2 trigger): attach the tracer to
                    // EVERY lowerdir of the chain (event attribution is by
                    // mount-root prefix — see `all_lowerdirs`) and let it record
                    // reads during pod startup. On settle the OPTIMIZE stage
                    // runs (reusing stage 1's work dir) and re-uploads the
                    // optimized sidecar that the next pod (or peer node) picks
                    // up via the resolve_auto_accel_mount branch above. The
                    // snapshot key is the holder so remove() shrinks tracer
                    // state via detach_holder.
                    if let Some(image_ref) = image_ref {
                        for image_root in all_lowerdirs(&mounts) {
                            if let Err(e) =
                                self.access_tracer.attach(&image_ref, &image_root, &key)
                            {
                                debug!(image = %image_ref, root = %image_root.display(), error = %e, "access_tracer attach failed");
                            }
                        }
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

            if let Some((_, daemon_mnt)) = self.resolve_nydus_mount(&parent, &labels, &key).await? {
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
            let stat = match store.stat(&key) {
                Ok(info) => Some(info),
                Err(e) => {
                    warn!(key, error = %e, "snapshot stat failed during remove; a daemon release may be missed");
                    self.metrics.record_daemon_release_missing();
                    None
                }
            };
            let parent = stat.as_ref().and_then(|info| info.parent.clone());
            let labels = stat
                .as_ref()
                .map(|info| info.labels.clone())
                .unwrap_or_default();
            let release_target = if let Some(parent) = parent.as_deref() {
                match self.overlay.nydus_meta_info(store, parent, &labels) {
                    Ok(meta) => meta.map(|meta| meta.image_ref),
                    Err(e) => {
                        warn!(key, error = %e, "daemon resolution failed during remove; a daemon release may be missed");
                        self.metrics.record_daemon_release_missing();
                        None
                    }
                }
            } else {
                None
            };
            // Auto-accel / referrer mounts have no nydus meta layer in their
            // chain; prepare() stamped the serving image on the snapshot.
            let stamped_target = labels
                .get(crate::source::labels::NYDUS_DAEMON_IMAGE_REF)
                .cloned();
            {
                // remove_dir_all over an arbitrarily large snapshot tree —
                // never inline on the shared gRPC reactor thread.
                let overlay = self.overlay.clone();
                let store = Arc::clone(&self.store);
                let remove_key = key.clone();
                blocking::unblock(move || overlay.remove(&store, &remove_key))
                    .await
                    .inspect(|_| debug!(key, "removed snapshot"))
                    .map_err(|e| {
                        warn!(key, error = %e, "remove snapshot failed");
                        SnapshotterError::internal(e.to_string())
                    })?;
            }
            for image_ref in release_target.iter().chain(
                stamped_target
                    .iter()
                    .filter(|s| release_target.as_ref() != Some(s)),
            ) {
                if let Err(e) = self.supervisor.release(image_ref, &key).await {
                    warn!(image_ref, error = %e, "failed to release nydus daemon refcount");
                }
            }
            // Shrink tracer state with the snapshot that attached it (no-op
            // for keys that never attached).
            self.access_tracer.detach_holder(&key);
            Ok(())
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    async fn list(
        &self,
        _snapshotter: String,
        filters: Vec<String>,
    ) -> Result<Self::InfoStream, Self::Error> {
        let timer = self.metrics.start_snapshot_operation("list");
        let result = async {
            let store = self.store.as_ref();

            // Parse containerd Walk filters (OR across the vec, AND within each
            // comma-separated string). ANY unsupported filter falls back to the
            // unfiltered list — safe because containerd/ctr post-filter the
            // stream themselves. `None` means no filtering (either no filter was
            // supplied, or the fallback path).
            let exprs = if filters.is_empty() {
                None
            } else {
                match parse_filters(&filters) {
                    Some(exprs) => Some(exprs),
                    None => {
                        warn!(
                            ?filters,
                            "unsupported walk filter; returning unfiltered list"
                        );
                        None
                    }
                }
            };

            let snapshots = store
                .list()
                .map_err(|e| SnapshotterError::internal(e.to_string()))?
                .into_iter()
                .filter(move |info| match &exprs {
                    Some(exprs) => snapshot_matches(info, exprs),
                    None => true,
                })
                .map(|info| Ok(info_to_snapshots(info)));
            Ok(Box::pin(futures::stream::iter(snapshots)) as Self::InfoStream)
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }

    /// Cleanup RPC. containerd calls this for orphan reclamation; run a single
    /// synchronous reconciler pass (recover daemons, sweep stale daemon dirs,
    /// cache GC, auto-zran debris) rather than the default no-op.
    async fn clear(&self) -> Result<(), Self::Error> {
        let timer = self.metrics.start_snapshot_operation("clear");
        let result = async {
            info!("cleanup RPC: running one-shot reconciler pass");
            self.reconciler.run_once().await.map_err(|e| {
                warn!(error = %e, "cleanup reconciler pass failed");
                SnapshotterError::internal(e.to_string())
            })
        }
        .await;
        timer.finish(snapshot_status_label(&result));
        result
    }
}

/// Start the gRPC proxy-plugin server on the configured Unix socket.
pub async fn serve(mut config: SnapshotterConfig) -> Result<()> {
    let work_dir = config.snapshotter.cache.work_dir.clone();
    let (probe_results, selected) = crate::probe::probe_and_promote_driver(
        &mut config.snapshotter.fs_drivers,
        config.snapshotter.fs_driver_policy,
        Some(&work_dir),
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

/// Build the snapshot store at the path the config implies. Separate from
/// `serve_with_supervisor` so the binary entry point can open the store before
/// the runtime spawns the server task — that way it can `persist_now()` on a
/// SIGTERM path without reaching into the server task to fish out its handle,
/// which matters because the server task may be cancelled by runtime drop
/// before its inner Drops fire.
pub fn open_store_for_config(config: &SnapshotterConfig) -> Result<Arc<SnapshotStore>> {
    std::fs::create_dir_all(&config.snapshotter.root)?;
    let root = PathBuf::from(&config.snapshotter.root);
    let store = Arc::new(SnapshotStore::open(&root.join("metadata.fjall"))?);
    // Import a legacy Go-snapshotter bbolt `metadata.db` (if one sits under
    // the root and the fjall store is fresh) so operators don't have to run
    // `nydus-migrate store` by hand. Logs and degrades on failure; when no
    // legacy db exists this is a single existence check.
    //
    // Stamp imported records with the node's actual resolved driver:
    // `config.snapshotter.fs_drivers.first()`, already reordered to the
    // probed/promoted driver by `probe_and_promote_driver`, which both
    // `serve()` (above) and `containerd-nydus.rs` run before calling this
    // function. The label is
    // non-authoritative (the live mount driver always comes from the node's
    // probed driver, never from a snapshot record; see
    // `migrate::auto_migrate_if_needed`), but a wrong label is still
    // misleading to an operator inspecting the store directly.
    #[cfg(feature = "migrate")]
    {
        let fs_driver = config
            .snapshotter
            .fs_drivers
            .first()
            .map(|driver| match driver.driver_type {
                crate::config::FsDriverType::Fanotify => "fanotify",
                crate::config::FsDriverType::Fusedev => "fusedev",
                crate::config::FsDriverType::Blockdev => "blockdev",
                crate::config::FsDriverType::Tarfs => "tarfs",
            })
            .unwrap_or("fusedev");
        crate::migrate::auto_migrate_at_startup(&root, &store, fs_driver);
    }
    Ok(store)
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

    // Deprecation notice for the Kubernetes node fan-out. Native Spegel libp2p
    // routing (v0.7.1+) is the default (`peer_discovery = "off"` for every
    // preset); the fan-out is an opt-in resilience fallback scheduled for
    // removal after a production soak of default-off. The code is retained
    // until then — this only warns.
    if config.snapshotter.peer_mirror.peer_discovery()
        == crate::config::PeerDiscoveryMode::Kubernetes
    {
        warn!(
            "peer_discovery = \"kubernetes\" is enabled: the Kubernetes node fan-out is a \
             DEPRECATED resilience fallback. Native Spegel libp2p routing is verified working \
             and is the default (peer_discovery = \"off\"); the fan-out is scheduled for removal \
             after a production soak. Remove the explicit setting to rely on native routing."
        );
    }

    // Optional TCP Prometheus endpoint (opt-in via `[snapshotter.metrics]`).
    // When `listen` is unset this block is skipped and metrics stay UDS-only.
    // When set, a one-route cyper-axum server exposes `GET /metrics` reusing
    // the same `SnapshotterMetrics` renderer as the sysctl UDS endpoint (no
    // metric text is duplicated).
    if let Some(listen) = config.snapshotter.metrics.listen.clone() {
        let metrics = metrics.clone();
        let cache = cache_manager.clone();
        compio::runtime::spawn(async move {
            if let Err(e) = crate::metrics::serve_metrics_tcp(listen, metrics, cache).await {
                warn!(error = %e, "Prometheus metrics TCP endpoint exited unexpectedly");
            }
        })
        .detach();
    }

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
    let (auto_zran, auto_accel_discovery, containerd_lookup_for_discovery, content_store_for_recon) =
        if config.snapshotter.auto_zran.enable {
            let content_store =
                crate::content_store::ContentStoreClient::new(&config.snapshotter.containerd)
                    .context("connect to containerd content store")?;
            // gRPC-backed lookup: image walks go over Images.List +
            // Content.Read, never by spawning crictl/ctr per image — a
            // CLI walk takes ~80 s per refresh on a loaded node and
            // head-of-line-blocks every other snapshotter call.
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
            // Peer-mirror local self-check: turns the silent "local mirror not
            // advertising local content" misconfiguration (e.g. a broken
            // registries.yaml) into a loud, diagnosable warning + the
            // `snapshotter_peer_mirror_selfcheck_ok` gauge. It probes a
            // node-local auto-accel sidecar digest against ONLY the local mirror
            // endpoint, so it can only run on the auto_zran path (where a
            // content store and locally-produced sidecars exist). Best-effort,
            // detached background loop — never blocks or crashes startup.
            if config.snapshotter.peer_mirror.is_enabled()
                && let Some(selfcheck) =
                    crate::peer_mirror_selfcheck::PeerMirrorSelfCheck::from_config(
                        content_store.clone(),
                        &config.snapshotter.peer_mirror,
                        metrics.clone(),
                    )
            {
                compio::runtime::spawn(async move { selfcheck.run_loop().await }).detach();
            }
            let discovery = crate::auto_accel_sidecar::AutoAccelDiscovery::new(
                content_store.clone(),
                &config.snapshotter.root,
                &config.snapshotter.peer_mirror,
            );
            (
                auto_zran,
                Some(discovery),
                Some(containerd_lookup),
                Some(content_store),
            )
        } else {
            (None, None, None, None)
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
        .with_grpc_socket(socket_path.clone())
        .with_mount_probe_timeout(parse_duration(
            &config.snapshotter.recon.mount_probe_timeout,
        )?)
        .build();
        compio::runtime::spawn(async move {
            if let Err(e) = serve_sysctl_unix(sysctl_path, controller).await {
                warn!(error = %e, "system-controller API exited unexpectedly");
            }
        })
        .detach();
    }

    // Cheap self-healing passes tick at [snapshotter.recon] period; the
    // expensive passes (cache GC, auto-zran sweep, sidecar GC) stay on the
    // cache gc_period cadence.
    let mut reconciler = Reconciler::new(
        supervisor.clone(),
        store.clone(),
        parse_duration(&config.snapshotter.recon.period)?,
    )
    .with_slow_interval(parse_duration(&config.snapshotter.cache.gc_period)?)
    .with_cache_gc(cache_manager, cache_gc_policy)
    .with_refcount_recon(Arc::new(overlay.clone()));
    if config.snapshotter.recon.mount_probe {
        reconciler = reconciler.with_mount_probe(parse_duration(
            &config.snapshotter.recon.mount_probe_timeout,
        )?);
    }
    // Sweep abandoned auto-zran job dirs. Retention semantics and why sweeping
    // a retained base dir is safe are documented on
    // `AUTO_ZRAN_STALE_JOB_MAX_AGE`.
    if let Some(manager) = auto_zran.clone() {
        reconciler = reconciler.with_auto_zran_sweep(
            config.snapshotter.auto_zran.work_dir.clone(),
            AUTO_ZRAN_STALE_JOB_MAX_AGE,
            manager,
        );
        // Opt-in: the re-optimize sweep re-enqueues every persisted profile,
        // which re-drives non-candidate images (see the config field doc), so
        // it stays off until sidecar-Base gating lands.
        if config.snapshotter.auto_zran.reoptimize_stuck_base {
            reconciler = reconciler.with_reoptimize_profiles(
                crate::prefetch_profile::PrefetchProfileStore::from_cache_root(
                    &config.snapshotter.cache.work_dir,
                ),
            );
        }
    }
    // Sidecar GC: without this sweep a deleted (or repointed) image's sidecar
    // record lives forever — and it transitively pins the original gzip layer
    // tree via its `gc.ref.content.*` labels, so image churn never frees disk.
    if let (Some(content_store), Some(lookup)) = (
        content_store_for_recon,
        containerd_lookup_for_discovery.clone(),
    ) {
        reconciler = reconciler.with_sidecar_gc(crate::recon::SidecarGcDeps {
            content_store,
            lookup,
            content_root: config.snapshotter.containerd.content_root(),
        });
    }
    // Share the reconciler between the background loop and the snapshotter's
    // Cleanup RPC (`clear()` → `run_once()`).
    let reconciler = Arc::new(reconciler);
    let reconciler_loop = reconciler.clone();
    compio::runtime::spawn(async move {
        if let Err(e) = reconciler_loop.run().await {
            warn!(error = %e, "reconciler exited unexpectedly");
        }
    })
    .detach();

    let snapshotter = NydusSnapshotter {
        config: config.clone(),
        store,
        overlay,
        supervisor,
        metrics,
        reconciler,
        access_tracer,
        auto_zran,
        auto_accel_discovery,
        containerd_lookup: containerd_lookup_for_discovery,
        containerd_content_root: if config.snapshotter.auto_zran.enable {
            Some(config.snapshotter.containerd.content_root())
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

    // Standard grpc.health.v1.Health service so containerd's proxy-plugin dialer
    // and grpc_health_probe can check readiness. tonic-health is a
    // runtime-agnostic tower service (tokio::sync primitives only, no runtime
    // spawn), so its `HealthServer` composes with `tonic::service::Routes`
    // exactly like the Snapshots service and rides the same cyper-axum
    // (hyper-on-compio) server — no tokio runtime, no second transport.
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    // Mark both the overall server ("") and the Snapshots service SERVING now
    // that the listener is bound. The empty service is what grpc_health_probe and
    // containerd's dialer check by default. There is no graceful-shutdown signal
    // wired into this serve loop (cyper-axum runs until the task is dropped), so
    // there is no NOT_SERVING transition to set here.
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    health_reporter
        .set_service_status(
            "containerd.services.snapshots.v1.Snapshots",
            tonic_health::ServingStatus::Serving,
        )
        .await;

    let app = tonic::service::Routes::new(grpc)
        .add_service(health_service)
        .into_axum_router();
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
        test_snapshotter_with_config(root, config)
    }

    fn test_snapshotter_with_config(root: &Path, config: SnapshotterConfig) -> NydusSnapshotter {
        let store = Arc::new(SnapshotStore::open(&root.join("metadata.fjall")).unwrap());
        let overlay = OverlayEngine::new(config.clone());
        let supervisor = Arc::new(DaemonSupervisor::new(config.clone()));
        let reconciler = Arc::new(Reconciler::new(
            supervisor.clone(),
            store.clone(),
            std::time::Duration::from_secs(3600),
        ));
        NydusSnapshotter {
            config,
            store,
            overlay,
            supervisor,
            metrics: Arc::new(SnapshotterMetrics::new()),
            reconciler,
            access_tracer: crate::access_tracer::AccessTracer::start(
                Default::default(),
                crate::prefetch_profile::PrefetchProfileStore::from_cache_root(root),
                None,
            ),
            auto_zran: None,
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

    /// The gating guarantee for the OFF path: with referrer detection disabled,
    /// a plain OCI prepare (even with an image-ref label) returns the overlay
    /// mounts untouched and performs zero referrer interaction. If the referrer
    /// branch were not gated on the flag, this prepare would instead attempt a
    /// live registry round-trip for the bogus ref. (The flag defaults ON, so
    /// this test disables it explicitly to exercise the fall-through path.)
    #[compio::test]
    async fn prepare_with_referrer_detect_off_returns_overlay_mounts() {
        let dir = tempdir().unwrap();
        let mut config = SnapshotterConfig::default();
        config.snapshotter.root = dir.path().to_path_buf();
        config.snapshotter.features.referrer_detect = false;
        let snapshotter = test_snapshotter_with_config(dir.path(), config);
        assert!(
            !snapshotter.config.snapshotter.features.referrer_detect,
            "referrer_detect must be off for this fall-through test"
        );

        let labels = HashMap::from([(
            crate::source::CRI_IMAGE_REF.to_string(),
            "registry.invalid.test/team/app:1".to_string(),
        )]);
        let mounts = snapshotter
            .prepare("prepare-plain".to_string(), String::new(), labels)
            .await
            .expect("plain prepare must succeed with referrer detection off");
        assert!(
            !mounts.is_empty(),
            "flag-off prepare must return the overlay mounts unchanged"
        );
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

    #[compio::test]
    async fn update_masked_merge_preserves_gc_labels() {
        use crate::store::SnapshotKind;
        let dir = tempdir().unwrap();
        let snapshotter = test_snapshotter(dir.path());
        snapshotter
            .store
            .create(
                "snap",
                None,
                SnapshotKind::Active,
                "fusedev",
                None,
                &labels(&[
                    ("containerd.io/gc.ref.content.0", "sha256:abc"),
                    ("app", "old"),
                ]),
            )
            .unwrap();

        let mut info = Info {
            name: "snap".to_string(),
            ..Default::default()
        };
        info.labels = labels(&[("app", "new")]);
        let updated = snapshotter
            .update(info, Some(vec!["labels.app".to_string()]))
            .await
            .unwrap();

        assert_eq!(updated.labels.get("app").map(String::as_str), Some("new"));
        assert_eq!(
            updated
                .labels
                .get("containerd.io/gc.ref.content.0")
                .map(String::as_str),
            Some("sha256:abc"),
            "masked update must not clobber the GC-root label"
        );
    }

    #[compio::test]
    async fn update_replace_all_when_mask_absent() {
        use crate::store::SnapshotKind;
        let dir = tempdir().unwrap();
        let snapshotter = test_snapshotter(dir.path());
        snapshotter
            .store
            .create(
                "snap",
                None,
                SnapshotKind::Active,
                "fusedev",
                None,
                &labels(&[("old", "1")]),
            )
            .unwrap();

        let info = Info {
            name: "snap".to_string(),
            labels: labels(&[("only", "kept")]),
            ..Default::default()
        };
        let updated = snapshotter.update(info, None).await.unwrap();
        assert!(!updated.labels.contains_key("old"));
        assert_eq!(updated.labels.get("only").map(String::as_str), Some("kept"));
    }

    #[compio::test]
    async fn update_missing_snapshot_is_not_found() {
        // Both mask paths must agree: updating a snapshot that does not exist
        // is NotFound, not Internal — including the common absent-mask
        // replace-all path, which must not skip the existence check.
        let dir = tempdir().unwrap();
        let snapshotter = test_snapshotter(dir.path());
        let info = Info {
            name: "missing".to_string(),
            labels: labels(&[("k", "v")]),
            ..Default::default()
        };
        let err = snapshotter
            .update(info, None)
            .await
            .expect_err("replace-all update of a missing snapshot must fail");
        assert_eq!(status_code(err), snapshots::tonic::Code::NotFound);
    }

    #[compio::test]
    async fn update_unsupported_fieldpath_is_invalid_argument() {
        use crate::store::SnapshotKind;
        let dir = tempdir().unwrap();
        let snapshotter = test_snapshotter(dir.path());
        snapshotter
            .store
            .create(
                "snap",
                None,
                SnapshotKind::Active,
                "fusedev",
                None,
                &labels(&[]),
            )
            .unwrap();

        let info = Info {
            name: "snap".to_string(),
            ..Default::default()
        };
        let err = snapshotter
            .update(info, Some(vec!["parent".to_string()]))
            .await
            .expect_err("unsupported fieldpath must be rejected");
        assert_eq!(status_code(err), snapshots::tonic::Code::InvalidArgument);
    }

    #[compio::test]
    async fn clear_runs_a_reconciler_pass() {
        // With no daemons/mounts the pass is a clean no-op, but it must return
        // Ok — i.e. the Cleanup RPC is wired to the reconciler, not the default.
        let dir = tempdir().unwrap();
        let snapshotter = test_snapshotter(dir.path());
        snapshotter.clear().await.unwrap();
    }

    #[compio::test]
    async fn list_filters_by_key() {
        use crate::store::SnapshotKind;
        use futures::StreamExt as _;
        let dir = tempdir().unwrap();
        let snapshotter = test_snapshotter(dir.path());
        for key in ["a", "b", "c"] {
            snapshotter
                .store
                .create(
                    key,
                    None,
                    SnapshotKind::Active,
                    "fusedev",
                    None,
                    &labels(&[]),
                )
                .unwrap();
        }

        let stream = snapshotter
            .list(String::new(), vec!["key==b".to_string()])
            .await
            .unwrap();
        let got: Vec<_> = stream.collect().await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref().unwrap().name, "b");
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

    // ---- Field-mask merge (update) ----

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parse_label_mask_bare_labels_replace_all() {
        assert_eq!(
            parse_label_mask(&["labels".to_string()]).unwrap(),
            LabelMask::ReplaceAll
        );
    }

    #[test]
    fn parse_label_mask_collects_per_key_merges() {
        assert_eq!(
            parse_label_mask(&["labels.foo".to_string(), "labels.bar".to_string()]).unwrap(),
            LabelMask::Merge(vec!["foo".to_string(), "bar".to_string()])
        );
    }

    #[test]
    fn parse_label_mask_bare_labels_wins_over_merge() {
        // A bare `labels` alongside per-key paths collapses to replace-all, and
        // every path is still validated (no early return hiding a bad field).
        assert_eq!(
            parse_label_mask(&["labels.foo".to_string(), "labels".to_string()]).unwrap(),
            LabelMask::ReplaceAll
        );
    }

    #[test]
    fn parse_label_mask_rejects_unsupported_field() {
        assert_eq!(
            parse_label_mask(&["parent".to_string()]).unwrap_err(),
            "parent".to_string()
        );
        assert_eq!(
            parse_label_mask(&["labels.foo".to_string(), "kind".to_string()]).unwrap_err(),
            "kind".to_string()
        );
    }

    #[test]
    fn merge_labels_preserves_unmasked_keys() {
        // The GC-root clobber bug: a `labels.app` update must NOT drop an
        // existing `containerd.io/gc.ref.content` label.
        let existing = labels(&[
            ("containerd.io/gc.ref.content.0", "sha256:abc"),
            ("app", "old"),
        ]);
        let incoming = labels(&[("app", "new")]);
        let merged = merge_labels(&existing, &incoming, &["app".to_string()]);
        assert_eq!(merged.get("app").unwrap(), "new");
        assert_eq!(
            merged.get("containerd.io/gc.ref.content.0").unwrap(),
            "sha256:abc"
        );
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merge_labels_absent_incoming_key_becomes_empty() {
        // Matches containerd's `updated.Labels[key] = info.Labels[key]` (a Go map
        // miss yields "").
        let existing = labels(&[("keep", "yes")]);
        let incoming = labels(&[]);
        let merged = merge_labels(&existing, &incoming, &["gone".to_string()]);
        assert_eq!(merged.get("keep").unwrap(), "yes");
        assert_eq!(merged.get("gone").map(String::as_str), Some(""));
    }

    // ---- Walk filter parsing + matching (list) ----

    fn snap(key: &str, parent: Option<&str>, kind: &str, lbls: &[(&str, &str)]) -> SnapshotInfo {
        SnapshotInfo {
            key: key.to_string(),
            parent: parent.map(str::to_string),
            kind: kind.to_string(),
            fs_driver: "fusedev".to_string(),
            image_ref: None,
            created_at: 0,
            updated_at: 0,
            labels: labels(lbls),
        }
    }

    #[test]
    fn parse_filter_term_supports_all_fields() {
        assert_eq!(
            parse_filter_term("key==foo"),
            Some(FilterTerm::Name("foo".to_string()))
        );
        assert_eq!(
            parse_filter_term("name==foo"),
            Some(FilterTerm::Name("foo".to_string()))
        );
        assert_eq!(
            parse_filter_term("parent==p"),
            Some(FilterTerm::Parent("p".to_string()))
        );
        assert_eq!(
            parse_filter_term("kind==committed"),
            Some(FilterTerm::Kind("committed".to_string()))
        );
        assert_eq!(
            parse_filter_term(r#"labels."io.k8s/x"==v"#),
            Some(FilterTerm::Label {
                key: "io.k8s/x".to_string(),
                value: "v".to_string(),
            })
        );
    }

    #[test]
    fn parse_filter_term_strips_quoted_values() {
        assert_eq!(
            parse_filter_term(r#"key=="quoted val""#),
            Some(FilterTerm::Name("quoted val".to_string()))
        );
    }

    #[test]
    fn parse_filter_term_rejects_unsupported() {
        assert_eq!(parse_filter_term("key~=regex"), None); // regex operator
        assert_eq!(parse_filter_term("bogus==x"), None); // unknown field
        assert_eq!(parse_filter_term("key"), None); // no operator/existence
        assert_eq!(parse_filter_term(r#"labels.""==v"#), None); // empty label key
    }

    #[test]
    fn parse_filters_and_within_a_string() {
        let exprs = parse_filters(&["key==foo,parent==bar".to_string()]).unwrap();
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].len(), 2);
    }

    #[test]
    fn parse_filters_none_on_any_unsupported() {
        assert!(parse_filters(&["key==foo".to_string(), "weird==x".to_string()]).is_none());
    }

    #[test]
    fn snapshot_matches_and_semantics_within_expr() {
        let exprs = parse_filters(&["key==k1,parent==p1".to_string()]).unwrap();
        let hit = snap("k1", Some("p1"), "kind_active", &[]);
        let miss = snap("k1", Some("other"), "kind_active", &[]);
        assert!(snapshot_matches(&hit, &exprs));
        assert!(!snapshot_matches(&miss, &exprs));
    }

    #[test]
    fn snapshot_matches_or_semantics_across_strings() {
        // Two filter strings are OR'd (containerd `ParseAll`).
        let exprs = parse_filters(&["key==a".to_string(), "key==b".to_string()]).unwrap();
        assert!(snapshot_matches(
            &snap("a", None, "kind_active", &[]),
            &exprs
        ));
        assert!(snapshot_matches(
            &snap("b", None, "kind_active", &[]),
            &exprs
        ));
        assert!(!snapshot_matches(
            &snap("c", None, "kind_active", &[]),
            &exprs
        ));
    }

    #[test]
    fn snapshot_matches_label_and_kind_and_parent() {
        let exprs = parse_filters(&[r#"labels."role"==base,kind==committed"#.to_string()]).unwrap();
        let hit = snap("k", Some("p"), "kind_committed", &[("role", "base")]);
        let wrong_kind = snap("k", Some("p"), "kind_active", &[("role", "base")]);
        let wrong_label = snap("k", Some("p"), "kind_committed", &[("role", "app")]);
        assert!(snapshot_matches(&hit, &exprs));
        assert!(!snapshot_matches(&wrong_kind, &exprs));
        assert!(!snapshot_matches(&wrong_label, &exprs));
    }

    #[test]
    fn snapshot_matches_empty_exprs_matches_all() {
        assert!(snapshot_matches(&snap("x", None, "kind_active", &[]), &[]));
    }

    #[test]
    fn snapshot_matches_parent_empty_string_for_rootless() {
        let exprs = parse_filters(&["parent==".to_string()]).unwrap();
        assert!(snapshot_matches(
            &snap("root", None, "kind_committed", &[]),
            &exprs
        ));
        assert!(!snapshot_matches(
            &snap("child", Some("root"), "kind_active", &[]),
            &exprs
        ));
    }

    #[test]
    fn parent_chain_digest_handles_chain_root_snapshot() {
        // Some prepare keys are bare ids (chain root, sandboxes) — no
        // digest suffix at all. Return None so auto-accel cleanly skips
        // this snapshot rather than passing a garbage key to the cache.
        assert_eq!(parent_chain_digest("k8s.io/2/extract-12345-RC1f"), None);
    }
}
