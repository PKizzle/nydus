// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Image-ref lookup by inspecting containerd's image store.
//!
//! containerd 2.x (as shipped in k3s ≥ v1.36) does not forward the
//! `containerd.io/snapshot/cri.image-ref` label to proxy-plugin snapshotters
//! at container Prepare time. To still resolve the image reference for a
//! given snapshot chainID (or Nydus bootstrap blob digest) we walk all
//! images known to containerd, fetch their manifests and record the
//! digest → image-ref mapping in a small in-memory cache.
//!
//! Data access goes through the containerd gRPC API (`Images.List` +
//! `Content.Read` via [`ContentStoreClient`]) when a client is wired in;
//! the legacy `crictl` / `ctr` CLI walk remains only as a fallback for
//! binaries constructed without one. The CLI fallback spawns the ~200 MB
//! k3s binary once per image, which on a loaded node turns a refresh into
//! a minute-plus stall — never run it on the snapshotter's gRPC runtime
//! (every caller here is async and the fallback is pushed through
//! `blocking::unblock`).
//!
//! Refreshes are single-flight and rate-limited: concurrent cache misses
//! await one shared walk instead of each starting their own, and a walk
//! that just completed is not repeated for `REFRESH_MIN_INTERVAL` even on
//! a miss (a chainID that wasn't found won't appear by walking again two
//! seconds later — it shows up when containerd finishes pulling the image,
//! which the next interval-spaced refresh observes).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::content_store::{ContentStoreClient, is_not_found, is_rpc_failure};

/// Acquire a lock without panicking on poisoning. A previous panic while a
/// lock was held would only have left the cache in a partially-populated
/// state; the worst case is a redundant containerd refresh, which is safe.
fn lock_cache<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

const NYDUS_BOOTSTRAP_ANNOTATION: &str = "containerd.io/snapshot/nydus-bootstrap";

/// Minimum spacing between two full image-store walks. A refresh is only
/// triggered by a cache miss; back-to-back misses (e.g. several pods of a
/// not-yet-pulled image scheduling together) must coalesce instead of
/// stampeding containerd.
const REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(15);

pub struct ContainerdLookup {
    /// Cache: snapshot key digest (chainID **or** layer digest, `sha256:…`)
    /// → image ref. Both are populated so a lookup using either kind of
    /// digest succeeds.
    cache: Mutex<HashMap<String, String>>,
    /// gRPC client for containerd's Images + Content services. `None`
    /// only in legacy constructions — the CLI fallback then applies.
    content_store: Option<ContentStoreClient>,
    /// Single-flight gate for refreshes. Holding the lock across the walk
    /// makes concurrent missers await the same walk; the instant records
    /// when the last walk finished so misses inside
    /// `REFRESH_MIN_INTERVAL` skip straight to "miss" without walking.
    refresh_gate: async_lock::Mutex<Option<Instant>>,
}

impl Default for ContainerdLookup {
    fn default() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            content_store: None,
            refresh_gate: async_lock::Mutex::new(None),
        }
    }
}

#[derive(Deserialize)]
struct CrictlImages {
    images: Vec<CrictlImage>,
}

#[derive(Deserialize, Default)]
struct CrictlImage {
    #[serde(default)]
    #[serde(rename = "repoTags")]
    repo_tags: Vec<String>,
    #[serde(default)]
    #[serde(rename = "repoDigests")]
    repo_digests: Vec<String>,
}

#[derive(Deserialize)]
struct OciManifest {
    #[serde(default)]
    layers: Vec<OciDescriptor>,
    #[serde(default)]
    config: Option<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    digest: String,
    #[serde(default)]
    annotations: HashMap<String, String>,
    #[serde(default, rename = "mediaType")]
    media_type: String,
}

#[derive(Deserialize)]
struct OciImageConfig {
    rootfs: OciRootfs,
}

#[derive(Deserialize)]
struct OciRootfs {
    #[serde(default, rename = "diff_ids")]
    diff_ids: Vec<String>,
}

impl ContainerdLookup {
    /// Construct with a containerd gRPC client (preferred — all reads go
    /// through Images.List / Content.Read, no subprocess spawns).
    pub fn new(content_store: ContentStoreClient) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            content_store: Some(content_store),
            refresh_gate: async_lock::Mutex::new(None),
        }
    }

    /// Legacy construction without a gRPC client; every read falls back to
    /// `crictl` / `ctr` subprocesses (run on the blocking pool).
    pub fn new_cli_only() -> Self {
        Self::default()
    }

    /// Look up the image ref for a given bootstrap layer / topmost chain
    /// digest. Returns:
    ///
    /// - `Ok(Some(image_ref))` — hit.
    /// - `Ok(None)` — refresh succeeded but no image references this digest
    ///   (genuine miss).
    /// - `Err(_)` — couldn't refresh (containerd unreachable, JSON
    ///   unparsable, etc.). Distinguishing this from a miss lets callers
    ///   log loudly when discovery is broken vs simply absent.
    pub async fn lookup(&self, bootstrap_digest: &str) -> Result<Option<String>> {
        if let Some(r) = lock_cache(&self.cache).get(bootstrap_digest) {
            return Ok(Some(r.clone()));
        }
        self.refresh_coalesced().await?;
        let hit = lock_cache(&self.cache).get(bootstrap_digest).cloned();
        if hit.is_none() {
            info!(
                bootstrap = %bootstrap_digest,
                "no containerd image found containing nydus bootstrap digest"
            );
        }
        Ok(hit)
    }

    /// Cache-only lookup: never walks containerd, never blocks. For sync
    /// call sites (e.g. `OverlayEngine::nydus_meta_info`'s last-resort
    /// fallback) that share this instance with the async prepare path —
    /// they read whatever the async lookups have already learned.
    pub fn lookup_cached(&self, bootstrap_digest: &str) -> Option<String> {
        lock_cache(&self.cache).get(bootstrap_digest).cloned()
    }

    /// Run (or await) one image-store walk. Misses arriving while a walk
    /// is in flight wait for it and re-check the cache; misses arriving
    /// within `REFRESH_MIN_INTERVAL` of the last walk return immediately.
    async fn refresh_coalesced(&self) -> Result<()> {
        let mut last_walk = self.refresh_gate.lock().await;
        if let Some(at) = *last_walk
            && at.elapsed() < REFRESH_MIN_INTERVAL
        {
            return Ok(());
        }
        let result = self.refresh().await;
        *last_walk = Some(Instant::now());
        result
    }

    async fn refresh(&self) -> Result<()> {
        let mut map: HashMap<String, String> = HashMap::new();
        let failed = match &self.content_store {
            Some(cs) => self.refresh_via_grpc(cs, &mut map).await?,
            None => {
                // CLI fallback: spawning crictl/ctr is slow and blocking —
                // keep it off the gRPC runtime.
                let (walked, failed) = blocking::unblock(walk_images_via_cli).await?;
                map = walked;
                failed
            }
        };
        let count = map.len();
        let mut cache = lock_cache(&self.cache);
        for (k, v) in map {
            cache.entry(k).or_insert(v);
        }
        info!(
            entries = count,
            failed,
            total = cache.len(),
            "containerd image-ref cache refreshed"
        );
        Ok(())
    }

    /// Walk every image record into `map`; returns how many records
    /// resolved to nothing. Their digests come from Images.List, so a
    /// failure is a record whose content is missing or unreadable.
    async fn refresh_via_grpc(
        &self,
        cs: &ContentStoreClient,
        map: &mut HashMap<String, String>,
    ) -> Result<usize> {
        let records = cs.images_list().await.context("containerd Images.List")?;
        let mut failed = 0;
        for group in group_records_by_target(&records) {
            if let Err(e) = walk_manifest_via_grpc(cs, &group.target, &group.display_ref, map).await
            {
                failed += 1;
                if is_rpc_failure(&e) {
                    debug!(image = %group.display_ref, error = %format_args!("{e:#}"), "image walk failed");
                } else {
                    warn!(image = %group.display_ref, error = %format_args!("{e:#}"), "image walk failed");
                }
            }
        }
        Ok(failed)
    }

    /// Forward direction: resolve an image reference to its manifest digest
    /// and ordered gzip layer list (lower→upper), with each layer's on-disk
    /// path in containerd's content store. Returns an error if the image
    /// isn't known to containerd, has no compatible architecture in a
    /// multi-arch index, or carries no readable gzip layers.
    ///
    /// This is on-demand (not cached); the conversion path needs a single
    /// resolution per image and the call cost is two or three Content.Read
    /// RPCs for the manifest/index/config blobs.
    pub async fn manifest_info(
        &self,
        image_ref: &str,
        content_root: &std::path::Path,
    ) -> Result<ManifestInfo> {
        match &self.content_store {
            Some(cs) => {
                self.manifest_info_via_grpc(cs, image_ref, content_root)
                    .await
            }
            None => {
                let image_ref = image_ref.to_string();
                let content_root = content_root.to_path_buf();
                blocking::unblock(move || manifest_info_via_cli(&image_ref, &content_root)).await
            }
        }
    }

    async fn manifest_info_via_grpc(
        &self,
        cs: &ContentStoreClient,
        image_ref: &str,
        content_root: &std::path::Path,
    ) -> Result<ManifestInfo> {
        // Exact-name fast path first (`name:tag` / `name@sha256:...`).
        let target = match cs.images_get(image_ref).await? {
            Some(info) => Some(info.digest),
            None => {
                // The ref may be name-only (`docker.io/library/nginx`) —
                // match it against the name part of every record, exactly
                // like the legacy crictl matcher did.
                let records = cs.images_list().await.context("containerd Images.List")?;
                records
                    .iter()
                    .find(|r| record_matches_ref(&r.name, image_ref))
                    .map(|r| r.target_digest.clone())
            }
        };
        let Some(target) = target else {
            bail!(
                "image {image_ref} not found in containerd image store; \
                 make sure it's been pulled at least once"
            );
        };
        let (final_digest, layers) =
            resolve_gzip_layers_via_grpc(cs, &target, content_root).await?;
        Ok(ManifestInfo {
            manifest_digest: final_digest,
            layers,
        })
    }
}

/// One containerd image record (name + manifest/index target digest).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageRecord {
    pub name: String,
    pub target_digest: String,
}

struct RecordGroup {
    target: String,
    display_ref: String,
}

/// Rank an image-record name by its usefulness as a registry reference.
/// Higher is better:
///   3 — tag-form full ref (`host/repo:tag`)
///   2 — digest-form ref (`host/repo@sha256:...` — repo still resolvable)
///   1 — name-only ref (`host/repo`)
///   0 — bare digest / image-ID record (`sha256:<hex>`): containerd's CRI
///       plugin stores one of these for EVERY pulled image, and it is
///       USELESS as a registry ref — parsing it yields repo "sha256"
///       (docker.io-normalized to "library/sha256"), so a daemon built from
///       it fails every blob fetch with UNAUTHORIZED and containers EIO.
fn ref_name_rank(name: &str) -> u8 {
    if name.starts_with("sha256:") || name.starts_with("sha512:") {
        return 0;
    }
    if name.contains('@') {
        return 2;
    }
    // Tag split as in record_matches_ref: the last `:` is a tag separator
    // only when the remainder has no `/` (registry ports are not tags).
    match name.rsplit_once(':') {
        Some((_, tag)) if !tag.is_empty() && !tag.contains('/') => 3,
        _ => 1,
    }
}

/// Group image records by target digest, choosing the highest-ranked name
/// (see [`ref_name_rank`]) as the display ref — real tag refs first, then
/// `repo@digest` refs; bare image-ID records (`sha256:...`) never win, and a
/// group consisting ONLY of image-ID records is dropped entirely: mapping a
/// chain to a bare digest poisons every consumer downstream (registry
/// backend, auto-accel routing, capture).
fn group_records_by_target(records: &[ImageRecord]) -> Vec<RecordGroup> {
    let mut by_target: HashMap<&str, &str> = HashMap::new();
    for record in records {
        let entry = by_target.entry(record.target_digest.as_str());
        match entry {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(record.name.as_str());
            }
            std::collections::hash_map::Entry::Occupied(mut o) => {
                if ref_name_rank(record.name.as_str()) > ref_name_rank(o.get()) {
                    o.insert(record.name.as_str());
                }
            }
        }
    }
    by_target
        .into_iter()
        .filter_map(|(target, chosen)| {
            if ref_name_rank(chosen) == 0 {
                debug!(
                    target,
                    name = chosen,
                    "skipping image group with only image-ID records (no usable ref)"
                );
                return None;
            }
            Some(RecordGroup {
                target: target.to_string(),
                display_ref: chosen.to_string(),
            })
        })
        .collect()
}

/// Does an image-record name refer to `image_ref`? Exact match, or the
/// record's name part (before `@digest` / `:tag`) equals a name-only ref.
fn record_matches_ref(record_name: &str, image_ref: &str) -> bool {
    if record_name == image_ref {
        return true;
    }
    if let Some((name, _)) = record_name.split_once('@')
        && name == image_ref
    {
        return true;
    }
    // Tag split: only treat the last `:` as a tag separator when the
    // remainder has no `/` (avoids mangling registry ports like
    // `localhost:5000/img`).
    if let Some((name, tag)) = record_name.rsplit_once(':')
        && !tag.contains('/')
        && name == image_ref
    {
        return true;
    }
    false
}

async fn walk_manifest_via_grpc(
    cs: &ContentStoreClient,
    digest: &str,
    image_ref: &str,
    out: &mut HashMap<String, String>,
) -> Result<()> {
    let bytes = cs
        .fetch_bytes(digest)
        .await
        .with_context(|| format!("fetch manifest {digest}"))?;
    // Try as index first (multi-arch); if no `manifests` field, treat as
    // manifest. Recursion is bounded by OCI nesting (index → manifest).
    if let Ok(index) = serde_json::from_slice::<OciIndexWithPlatforms>(&bytes)
        && !index.manifests.is_empty()
    {
        let (host, rest) = walkable_children(&index);
        let mut host_results = Vec::with_capacity(host.len());
        for child in host {
            let result = Box::pin(walk_manifest_via_grpc(cs, child, image_ref, out)).await;
            if let Err(e) = &result {
                debug!(child = %child, error = %format_args!("{e:#}"), "host-platform child walk failed");
            }
            host_results.push(result);
        }
        let mut rest_resolved = false;
        if walk_rest_children(&host_results, is_not_found) {
            for child in rest {
                match Box::pin(walk_manifest_via_grpc(cs, child, image_ref, out)).await {
                    Ok(()) => rest_resolved = true,
                    Err(e) => {
                        debug!(child = %child, error = %format_args!("{e:#}"), "child walk failed")
                    }
                }
            }
        }
        return index_walk_result(digest, host_results, rest_resolved);
    }
    let manifest: OciManifest = serde_json::from_slice(&bytes)?;
    let bootstrap_indices = collect_bootstrap_layers(&manifest, image_ref, out);
    let Some(cfg_desc) = manifest.config.as_ref() else {
        return Ok(());
    };
    let cfg_bytes = cs
        .fetch_bytes(&cfg_desc.digest)
        .await
        .with_context(|| format!("fetch image config for {image_ref}"))?;
    let cfg: OciImageConfig = serde_json::from_slice(&cfg_bytes)
        .with_context(|| format!("parse image config for {image_ref}"))?;
    register_chain_ids(image_ref, &cfg.rootfs.diff_ids, &bootstrap_indices, out);
    Ok(())
}

/// Record bootstrap-annotated layers into the cache map (by layer digest)
/// and return their indices for chainID registration. Shared between the
/// gRPC and CLI walks.
fn collect_bootstrap_layers(
    manifest: &OciManifest,
    image_ref: &str,
    out: &mut HashMap<String, String>,
) -> Vec<usize> {
    if manifest.layers.is_empty() && manifest.config.is_none() {
        // Typically an index whose `manifests` failed to parse (e.g. a
        // non-object `platform`) falling through to the manifest parse.
        debug!(image = %image_ref, "manifest has neither layers nor config; nothing to register");
    }
    let mut bootstrap_indices: Vec<usize> = Vec::new();
    for (i, layer) in manifest.layers.iter().enumerate() {
        let is_bootstrap = layer
            .annotations
            .get(NYDUS_BOOTSTRAP_ANNOTATION)
            .map(|s| s == "true")
            .unwrap_or(false);
        if is_bootstrap {
            debug!(
                bootstrap = %layer.digest,
                image = %image_ref,
                media_type = %layer.media_type,
                "discovered nydus bootstrap layer"
            );
            out.insert(layer.digest.clone(), image_ref.to_string());
            bootstrap_indices.push(i);
        }
    }
    bootstrap_indices
}

/// Pure registration step factored out of the walk so unit tests can pin
/// the chainID rules (topmost-for-any-image, bootstrap-layer-for-nydus)
/// without any containerd access.
fn register_chain_ids(
    image_ref: &str,
    diff_ids: &[String],
    bootstrap_indices: &[usize],
    out: &mut HashMap<String, String>,
) {
    let chain_ids = chain_ids(diff_ids);
    // Topmost chain_id makes auto-accel lookup work for STANDARD OCI
    // images on the prepare path — without this entry the chainID-to-
    // image-ref fallback in grpc::prepare misses every Run-of-nginx and
    // both capture and discovery are dead.
    if let Some(top) = chain_ids.last() {
        debug!(
            chain_id = %top,
            image = %image_ref,
            "registered topmost chainID for image"
        );
        out.insert(top.clone(), image_ref.to_string());
    }
    for &i in bootstrap_indices {
        if let Some(chain_id) = chain_ids.get(i) {
            debug!(
                chain_id = %chain_id,
                image = %image_ref,
                layer_index = i,
                "registered chainID for bootstrap layer"
            );
            out.insert(chain_id.clone(), image_ref.to_string());
        }
    }
}

/// Layer + manifest summary used by the auto-accel pipeline. The layer list
/// is gzip-only (skipping nydus-bootstrap / nydus-blob layers, which the
/// auto-accel path doesn't consume) in OCI manifest order, lower → upper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestInfo {
    /// The image's manifest digest (`sha256:...`). The auto-accel sidecar
    /// uses this as the `containerd.io/gc.ref.content.subject` label — an
    /// *outgoing* GC edge that keeps the original manifest (and its layers)
    /// alive while the sidecar exists, because the zran indexes read the
    /// original gzip layers from the content store at serve time. The
    /// sidecar's own lifetime is bounded by its synthetic Image record, which
    /// the reconciler deletes once the subject image is gone.
    pub manifest_digest: String,
    /// Gzip layers in device-table order with their on-disk content-store
    /// paths already resolved.
    pub layers: Vec<crate::local_accel::GzipLayer>,
}

/// Resolve an index/manifest digest to (manifest_digest, gzip_layers) for
/// the current host's architecture, reading blobs via gRPC. For a
/// single-manifest digest this is a pass-through; for a multi-arch index
/// we pick the matching child by GOARCH.
async fn resolve_gzip_layers_via_grpc(
    cs: &ContentStoreClient,
    digest: &str,
    content_root: &std::path::Path,
) -> Result<(String, Vec<crate::local_accel::GzipLayer>)> {
    // The digest is the image record's target or the host child picked
    // from it, never speculative, so a miss is worth a warning; "no host
    // match" and "no gzip layers" are normal for many images and stay at
    // the caller's debug.
    let bytes = cs
        .fetch_bytes(digest)
        .await
        .with_context(|| format!("fetch manifest {digest}"))
        .inspect_err(|e| {
            if !is_rpc_failure(e) {
                warn!(
                    manifest = %digest,
                    error = %format_args!("{e:#}"),
                    "image manifest not in content store; auto-accel falls back to overlay"
                );
            }
        })?;
    if let Ok(index) = serde_json::from_slice::<OciIndexWithPlatforms>(&bytes)
        && !index.manifests.is_empty()
    {
        let child = pick_host_arch_child(&index)
            .with_context(|| format!("no manifest in index {digest} matches this host"))?;
        return Box::pin(resolve_gzip_layers_via_grpc(cs, &child, content_root)).await;
    }
    let manifest: OciManifest = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parse manifest {digest}: {e}"))?;
    let layers = gzip_layers_from_manifest(&manifest, digest, content_root)?;
    Ok((digest.to_string(), layers))
}

/// Pick the index child matching the host architecture/OS. Pure so tests
/// can pin the GOARCH translation.
fn pick_host_arch_child(index: &OciIndexWithPlatforms) -> Option<String> {
    index
        .manifests
        .iter()
        .find(|child| is_host_platform(child))
        .map(|child| child.digest.clone())
}

/// Index children for the chainID map, split into `(host, rest)`: the
/// children matching the host architecture/OS (variants such as arm64/v8
/// and `os.features` all match), then every other child in index order.
/// containerd by default pulls only the host-platform child, so the rest
/// (foreign arches, `unknown/unknown` attestation manifests) are usually
/// absent and are walked only when `walk_rest_children` says so. That
/// fallback keeps indices without platform info, and images pulled for a
/// foreign platform (`--platform`, tarball import), resolvable.
fn walkable_children(index: &OciIndexWithPlatforms) -> (Vec<&str>, Vec<&str>) {
    let (mut host, mut rest) = (Vec::new(), Vec::new());
    for child in &index.manifests {
        let group = if is_host_platform(child) {
            &mut host
        } else {
            &mut rest
        };
        group.push(child.digest.as_str());
    }
    (host, rest)
}

/// Whether to walk the non-host children: only when no host child
/// resolved and every host failure is a miss (`is_miss`), so a transport
/// error or a broken host manifest never fans out to every foreign child.
/// True for an index with no host child.
fn walk_rest_children(
    host_results: &[Result<()>],
    is_miss: impl Fn(&anyhow::Error) -> bool,
) -> bool {
    host_results.iter().all(|r| r.as_ref().is_err_and(&is_miss))
}

/// Outcome of an index walk: Ok when any child resolved, otherwise one
/// error for the caller to log, preferring a host failure that is not a
/// plain miss because it says more.
fn index_walk_result(
    digest: &str,
    host_results: Vec<Result<()>>,
    rest_resolved: bool,
) -> Result<()> {
    if rest_resolved || host_results.iter().any(Result::is_ok) {
        return Ok(());
    }
    let mut errors: Vec<anyhow::Error> = host_results.into_iter().filter_map(Result::err).collect();
    if errors.is_empty() {
        bail!("no child manifest of index {digest} is in the content store");
    }
    let e = errors.swap_remove(errors.iter().position(|e| !is_not_found(e)).unwrap_or(0));
    if is_not_found(&e) {
        Err(e.context(format!(
            "host-platform manifest or config of index {digest} not in content store; \
             pull in flight or content missing"
        )))
    } else {
        Err(e.context(format!(
            "host-platform manifest of index {digest} unreadable"
        )))
    }
}

fn is_host_platform(child: &OciIndexEntry) -> bool {
    child.platform.as_ref().is_some_and(|p| {
        p.architecture == registry_client::host_go_arch() && p.os == std::env::consts::OS
    })
}

/// Filter a manifest's layers down to the gzip data layers the auto-accel
/// path consumes, resolving each to its on-disk content-store path. Pure
/// (filesystem check aside) and shared by the gRPC and CLI paths.
fn gzip_layers_from_manifest(
    manifest: &OciManifest,
    digest: &str,
    content_root: &std::path::Path,
) -> Result<Vec<crate::local_accel::GzipLayer>> {
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        // Skip nydus-bootstrap / nydus-blob layers — they're not gzip data
        // layers from the auto-accel path's perspective.
        let is_nydus = layer
            .annotations
            .get(NYDUS_BOOTSTRAP_ANNOTATION)
            .map(|s| s == "true")
            .unwrap_or(false)
            || layer.media_type.contains("nydus");
        if is_nydus {
            continue;
        }
        // zran gives random access into gzip streams only. Checked before the blob lookup so a
        // zstd image reports why it is not a candidate instead of failing inside the converter
        // on an unparsable tar header. Both `tar+gzip` (OCI) and `tar.gzip` (Docker) end in gzip.
        if !layer.media_type.ends_with("gzip") {
            bail!(
                "layer {} is {}; node-local acceleration needs gzip layers",
                layer.digest,
                layer.media_type
            );
        }
        let hex = layer
            .digest
            .strip_prefix("sha256:")
            .unwrap_or(&layer.digest);
        let path = content_root.join("blobs").join("sha256").join(hex);
        if !path.is_file() {
            bail!(
                "layer {} not present at {} (content store out of sync?)",
                layer.digest,
                path.display()
            );
        }
        layers.push(crate::local_accel::GzipLayer {
            digest: layer.digest.clone(),
            path,
        });
    }
    if layers.is_empty() {
        bail!("manifest {digest} has no gzip layers");
    }
    Ok(layers)
}

#[derive(Deserialize)]
struct OciIndexWithPlatforms {
    #[serde(default)]
    manifests: Vec<OciIndexEntry>,
}

#[derive(Deserialize)]
struct OciIndexEntry {
    digest: String,
    #[serde(default)]
    platform: Option<OciPlatform>,
}

#[derive(Deserialize)]
struct OciPlatform {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
}

/// Compute the containerd snapshot chainID list from an ordered list of
/// diff_ids. `chain[0] = diff_ids[0]`; `chain[i] = sha256(chain[i-1] + " " + diff_ids[i])`.
fn chain_ids(diff_ids: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(diff_ids.len());
    for (i, d) in diff_ids.iter().enumerate() {
        if i == 0 {
            out.push(d.clone());
        } else {
            let prev = &out[i - 1];
            let combined = format!("{} {}", prev, d);
            let hash = Sha256::digest(combined.as_bytes());
            out.push(format!("sha256:{}", hex_lower(hash.as_ref())));
        }
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("write to String cannot fail");
    }
    out
}

/// If `repo_tags` is non-empty prefer it (human-readable ref), else fall back to `name`.
fn preferred_ref(repo_tags: &[String], name: &str) -> String {
    repo_tags
        .first()
        .cloned()
        .unwrap_or_else(|| name.to_string())
}

// ---------------------------------------------------------------------------
// Legacy CLI fallback (no gRPC client wired). Each helper spawns crictl/ctr
// subprocesses — callers run these via `blocking::unblock` only.
// ---------------------------------------------------------------------------

/// CLI twin of `refresh_via_grpc`: the cache map and how many image
/// digests resolved to nothing.
fn walk_images_via_cli() -> Result<(HashMap<String, String>, usize)> {
    let out = run_first_ok(&[
        &["crictl", "images", "-o", "json"],
        &["k3s", "crictl", "images", "-o", "json"],
    ])?;
    let parsed: CrictlImages = serde_json::from_slice(&out)?;
    let mut map: HashMap<String, String> = HashMap::new();
    let mut failed = 0;
    for img in parsed.images {
        // Use repoDigests when available; they carry both ref and manifest
        // digest. repoTags alone carry no digest to walk from.
        for repo_digest in &img.repo_digests {
            // Format: "name@sha256:<digest>"
            let Some((name, manifest_digest)) = repo_digest.split_once('@') else {
                continue;
            };
            let ref_name = preferred_ref(&img.repo_tags, name);
            if let Err(e) = walk_manifest_via_cli(manifest_digest, &ref_name, &mut map) {
                failed += 1;
                warn!(image = %ref_name, error = %format_args!("{e:#}"), "image walk failed");
            }
        }
    }
    Ok((map, failed))
}

fn walk_manifest_via_cli(
    digest: &str,
    image_ref: &str,
    out: &mut HashMap<String, String>,
) -> Result<()> {
    let bytes = run_first_ok(&[
        &["ctr", "-n", "k8s.io", "content", "get", digest],
        &["k3s", "ctr", "-n", "k8s.io", "content", "get", digest],
    ])?;
    if let Ok(index) = serde_json::from_slice::<OciIndexWithPlatforms>(&bytes)
        && !index.manifests.is_empty()
    {
        let (host, rest) = walkable_children(&index);
        let mut host_results = Vec::with_capacity(host.len());
        for child in host {
            let result = walk_manifest_via_cli(child, image_ref, out);
            if let Err(e) = &result {
                debug!(child = %child, error = %format_args!("{e:#}"), "host-platform child walk failed");
            }
            host_results.push(result);
        }
        let mut rest_resolved = false;
        // A failed `ctr content get` does not say why, so every host
        // failure counts as a miss here.
        if walk_rest_children(&host_results, |_| true) {
            for child in rest {
                match walk_manifest_via_cli(child, image_ref, out) {
                    Ok(()) => rest_resolved = true,
                    Err(e) => {
                        debug!(child = %child, error = %format_args!("{e:#}"), "child walk failed")
                    }
                }
            }
        }
        return index_walk_result(digest, host_results, rest_resolved);
    }
    let manifest: OciManifest = serde_json::from_slice(&bytes)?;
    let bootstrap_indices = collect_bootstrap_layers(&manifest, image_ref, out);
    let Some(cfg_desc) = manifest.config.as_ref() else {
        return Ok(());
    };
    let cfg_bytes = run_first_ok(&[
        &["ctr", "-n", "k8s.io", "content", "get", &cfg_desc.digest],
        &[
            "k3s",
            "ctr",
            "-n",
            "k8s.io",
            "content",
            "get",
            &cfg_desc.digest,
        ],
    ])
    .with_context(|| format!("fetch image config for {image_ref}"))?;
    let cfg: OciImageConfig = serde_json::from_slice(&cfg_bytes)
        .with_context(|| format!("parse image config for {image_ref}"))?;
    register_chain_ids(image_ref, &cfg.rootfs.diff_ids, &bootstrap_indices, out);
    Ok(())
}

fn manifest_info_via_cli(image_ref: &str, content_root: &std::path::Path) -> Result<ManifestInfo> {
    let out = run_first_ok(&[
        &["crictl", "images", "-o", "json"],
        &["k3s", "crictl", "images", "-o", "json"],
    ])?;
    let parsed: CrictlImages = serde_json::from_slice(&out)?;
    for img in parsed.images {
        // Match either a repoTag (`name:tag`) or a repoDigest's name part
        // (`name@sha256:...`). The caller usually has the ref in tag form.
        let mut matched_manifest: Option<String> = None;
        for repo_digest in &img.repo_digests {
            if let Some((name, manifest_digest)) = repo_digest.split_once('@')
                && (name == image_ref || img.repo_tags.iter().any(|t| t == image_ref))
            {
                matched_manifest = Some(manifest_digest.to_string());
                break;
            }
        }
        let Some(manifest_digest) = matched_manifest else {
            continue;
        };
        let (final_digest, gzip_layers) =
            resolve_gzip_layers_via_cli(&manifest_digest, content_root)?;
        return Ok(ManifestInfo {
            manifest_digest: final_digest,
            layers: gzip_layers,
        });
    }
    bail!(
        "image {image_ref} not found in crictl images output; \
         make sure it's been pulled at least once"
    )
}

fn resolve_gzip_layers_via_cli(
    digest: &str,
    content_root: &std::path::Path,
) -> Result<(String, Vec<crate::local_accel::GzipLayer>)> {
    let bytes = run_first_ok(&[
        &["ctr", "-n", "k8s.io", "content", "get", digest],
        &["k3s", "ctr", "-n", "k8s.io", "content", "get", digest],
    ])?;
    if let Ok(index) = serde_json::from_slice::<OciIndexWithPlatforms>(&bytes)
        && !index.manifests.is_empty()
    {
        let child = pick_host_arch_child(&index)
            .with_context(|| format!("no manifest in index {digest} matches this host"))?;
        return resolve_gzip_layers_via_cli(&child, content_root);
    }
    let manifest: OciManifest = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parse manifest {digest}: {e}"))?;
    let layers = gzip_layers_from_manifest(&manifest, digest, content_root)?;
    Ok((digest.to_string(), layers))
}

/// Run the first command whose binary exists & exits successfully.
fn run_first_ok(candidates: &[&[&str]]) -> Result<Vec<u8>> {
    let mut last_err: Option<String> = None;
    for argv in candidates {
        let Some((prog, args)) = argv.split_first() else {
            continue;
        };
        match Command::new(prog).args(args).output() {
            Ok(o) if o.status.success() => return Ok(o.stdout),
            Ok(o) => {
                last_err = Some(format!(
                    "{} {:?} exited {}: {}",
                    prog,
                    args,
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                ));
            }
            Err(e) => {
                last_err = Some(format!("{prog} {args:?}: {e}"));
            }
        }
    }
    match last_err {
        Some(e) => {
            warn!(error = %e, "all containerd CLI candidates failed");
            bail!("all containerd CLI candidates failed: {e}")
        }
        None => bail!("no containerd CLI candidates provided"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_layers_reject_non_gzip_layers_before_reading_blobs() {
        let manifest: OciManifest = serde_json::from_value(serde_json::json!({ "layers": [
            { "digest": "sha256:aa", "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd" },
        ]}))
        .unwrap();
        // The content root does not exist: the media type must be rejected first.
        let err =
            gzip_layers_from_manifest(&manifest, "sha256:m", std::path::Path::new("/nonexistent"))
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("tar+zstd") && err.contains("needs gzip"),
            "{err}"
        );
    }

    fn index_from_json(json: serde_json::Value) -> OciIndexWithPlatforms {
        serde_json::from_value(json).expect("valid index JSON")
    }

    fn entry(digest: &str, arch: &str, os: &str) -> serde_json::Value {
        serde_json::json!({
            "digest": digest,
            "platform": { "architecture": arch, "os": os }
        })
    }

    /// A multi-arch index lists foreign arches and attestation manifests
    /// that containerd by default does not pull; the host child is walked
    /// first and the rest only as a fallback.
    #[test]
    fn walkable_children_puts_host_platform_first() {
        let host = registry_client::host_go_arch();
        let os = std::env::consts::OS;
        let foreign = if host == "amd64" { "s390x" } else { "amd64" };
        let index = index_from_json(serde_json::json!({ "manifests": [
            entry("sha256:foreign", foreign, os),
            entry("sha256:host", host, os),
            entry("sha256:ppc", "ppc64le", os),
            entry("sha256:attest-host", "unknown", "unknown"),
            entry("sha256:attest-foreign", "unknown", "unknown"),
            entry("sha256:other-os", host, "windows"),
        ]}));
        let (host_children, rest) = walkable_children(&index);
        assert_eq!(host_children, vec!["sha256:host"]);
        assert_eq!(
            rest,
            vec![
                "sha256:foreign",
                "sha256:ppc",
                "sha256:attest-host",
                "sha256:attest-foreign",
                "sha256:other-os",
            ]
        );
        assert_eq!(pick_host_arch_child(&index).as_deref(), Some("sha256:host"));
    }

    /// Variants (arm64/v8 vs bare arm64) and `os.features` (the nydus
    /// sibling of a dual-image index) all match the host, so no child that
    /// could be the host's manifest or its nydus bootstrap is demoted.
    #[test]
    fn walkable_children_keeps_every_host_variant() {
        let host = registry_client::host_go_arch();
        let os = std::env::consts::OS;
        let index = index_from_json(serde_json::json!({ "manifests": [
            entry("sha256:bare", host, os),
            { "digest": "sha256:v8",
              "platform": { "architecture": host, "os": os, "variant": "v8" } },
            { "digest": "sha256:nydus",
              "platform": { "architecture": host, "os": os,
                            "os.features": ["nydus.remoteimage.v1"] } },
            entry("sha256:foreign", "riscv-none", os),
        ]}));
        let (host_children, rest) = walkable_children(&index);
        assert_eq!(
            host_children,
            vec!["sha256:bare", "sha256:v8", "sha256:nydus"]
        );
        assert_eq!(rest, vec!["sha256:foreign"]);
    }

    /// Without platform info (or with no host match) every child is in the
    /// fallback set, and the fallback is always walked.
    #[test]
    fn walkable_children_falls_back_to_all_without_host_match() {
        let index = index_from_json(serde_json::json!({ "manifests": [
            { "digest": "sha256:a" },
            { "digest": "sha256:b", "platform": {} },
            entry("sha256:c", "riscv-none", "plan9"),
        ]}));
        let (host_children, rest) = walkable_children(&index);
        assert!(host_children.is_empty());
        assert_eq!(rest, vec!["sha256:a", "sha256:b", "sha256:c"]);
        assert!(walk_rest_children(&[], is_not_found));
        assert_eq!(pick_host_arch_child(&index), None);
    }

    fn not_found(digest: &str) -> Result<()> {
        Err(anyhow::Error::new(tonic::Status::not_found("gone"))
            .context(format!("fetch manifest {digest}")))
    }

    /// An image pulled for a foreign platform (`ctr pull --platform`, a
    /// foreign tarball import, binfmt emulation) has its own child locally
    /// but not the host child: the host child's NotFound falls through to
    /// the rest, and the foreign child resolving makes the index resolve.
    #[test]
    fn walkable_children_walks_foreign_child_when_host_child_missing() {
        let host = registry_client::host_go_arch();
        let os = std::env::consts::OS;
        let foreign = if host == "amd64" { "arm64" } else { "amd64" };
        let index = index_from_json(serde_json::json!({ "manifests": [
            entry("sha256:foreign", foreign, os),
            entry("sha256:host", host, os),
        ]}));
        let (host_children, rest) = walkable_children(&index);
        assert_eq!(host_children, vec!["sha256:host"]);
        assert_eq!(rest, vec!["sha256:foreign"]);

        assert!(walk_rest_children(
            &[not_found("sha256:host")],
            is_not_found
        ));
        assert!(index_walk_result("sha256:idx", vec![not_found("sha256:host")], true).is_ok());
    }

    /// The fallback never runs when a host child resolved or failed for a
    /// reason other than absence, and an index nothing resolved for is an
    /// error the refresh logs once, naming the expected cause.
    #[test]
    fn index_walk_stays_on_host_unless_every_host_child_is_missing() {
        let down = || Err(anyhow::Error::new(tonic::Status::unavailable("down")));
        assert!(!walk_rest_children(
            &[not_found("sha256:a"), Ok(())],
            is_not_found
        ));
        assert!(!walk_rest_children(&[down()], is_not_found));
        assert!(
            index_walk_result("sha256:idx", vec![not_found("sha256:a"), Ok(())], false).is_ok()
        );

        let err = index_walk_result("sha256:idx", vec![not_found("sha256:a")], false).unwrap_err();
        assert!(
            format!("{err:#}").contains("pull in flight or content missing"),
            "{err:#}"
        );
        assert!(is_not_found(&err));

        let err = index_walk_result("sha256:idx", vec![not_found("sha256:a"), down()], false)
            .unwrap_err();
        assert!(
            !is_not_found(&err),
            "the non-miss failure is reported: {err:#}"
        );

        let err = index_walk_result("sha256:idx", vec![], false).unwrap_err();
        assert!(err.to_string().contains("sha256:idx"), "{err}");
    }

    /// chainID computation is the contract with containerd's snapshot
    /// naming. `chain[0] = diff[0]`, `chain[i] = sha256(chain[i-1] + " " +
    /// diff[i])` — pin with a known-good vector.
    #[test]
    fn chain_ids_match_containerd_algorithm() {
        let diff_ids = vec![
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ];
        let chains = chain_ids(&diff_ids);
        assert_eq!(chains[0], diff_ids[0]);
        // sha256("sha256:aaa... sha256:bbb...") — computed once, pinned.
        let combined = format!("{} {}", diff_ids[0], diff_ids[1]);
        let expected = format!(
            "sha256:{}",
            hex_lower(Sha256::digest(combined.as_bytes()).as_ref())
        );
        assert_eq!(chains[1], expected);
    }

    #[test]
    fn register_chain_ids_registers_topmost_for_plain_images() {
        let mut out = HashMap::new();
        let diff_ids = vec!["sha256:layer0".to_string(), "sha256:layer1".to_string()];
        register_chain_ids("docker.io/library/nginx:1.27", &diff_ids, &[], &mut out);
        let chains = chain_ids(&diff_ids);
        assert_eq!(
            out.get(chains.last().unwrap()).map(String::as_str),
            Some("docker.io/library/nginx:1.27")
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn register_chain_ids_registers_bootstrap_layers() {
        let mut out = HashMap::new();
        let diff_ids = vec!["sha256:layer0".to_string(), "sha256:layer1".to_string()];
        register_chain_ids("reg/nydus:tag", &diff_ids, &[1], &mut out);
        let chains = chain_ids(&diff_ids);
        assert!(out.contains_key(&chains[1]));
        assert!(out.contains_key(chains.last().unwrap()));
    }

    #[test]
    fn preferred_ref_prefers_repo_tags() {
        assert_eq!(
            preferred_ref(
                &["docker.io/library/nginx:1.27".to_string()],
                "docker.io/library/nginx"
            ),
            "docker.io/library/nginx:1.27"
        );
        assert_eq!(
            preferred_ref(&[], "docker.io/library/nginx"),
            "docker.io/library/nginx"
        );
    }

    /// `record_matches_ref` replaces the crictl repoTags/repoDigests
    /// matcher — pin all three accepted shapes plus the registry-port
    /// corner case.
    #[test]
    fn record_matches_exact_tag_digest_and_name_only() {
        assert!(record_matches_ref(
            "docker.io/library/nginx:1.27",
            "docker.io/library/nginx:1.27"
        ));
        assert!(record_matches_ref(
            "docker.io/library/nginx@sha256:abc",
            "docker.io/library/nginx"
        ));
        assert!(record_matches_ref(
            "docker.io/library/nginx:1.27",
            "docker.io/library/nginx"
        ));
        assert!(!record_matches_ref(
            "docker.io/library/nginxy:1.27",
            "docker.io/library/nginx"
        ));
        // A registry port colon must not be mistaken for a tag separator.
        assert!(!record_matches_ref("localhost:5000/img", "localhost"));
    }

    /// Tag-form names win over digest-form names as the display ref —
    /// matches the legacy crictl `preferred_ref` behaviour.
    #[test]
    fn group_records_prefers_tag_form_display_ref() {
        let records = vec![
            ImageRecord {
                name: "docker.io/library/nginx@sha256:abc".to_string(),
                target_digest: "sha256:abc".to_string(),
            },
            ImageRecord {
                name: "docker.io/library/nginx:1.27".to_string(),
                target_digest: "sha256:abc".to_string(),
            },
        ];
        let groups = group_records_by_target(&records);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].display_ref, "docker.io/library/nginx:1.27");
        assert_eq!(groups[0].target, "sha256:abc");
    }

    /// REGRESSION (0.2.9-nydus mirrors EIO): containerd's CRI plugin stores a
    /// bare image-ID record (`sha256:<config digest>`) for every pulled
    /// image. The old `contains('@')` heuristic classified it as "tag form",
    /// so it could win as the display ref — and a daemon built from it
    /// fetched blobs from repo "library/sha256" (UNAUTHORIZED → EIO). The
    /// image-ID record must NEVER win, in either insertion order.
    #[test]
    fn group_records_never_selects_bare_image_id() {
        for order in [true, false] {
            let mut records = vec![
                ImageRecord {
                    name: "sha256:0c0da3558734bbf673448b752bb6c139cbd3ece8060c6589370280b8ba631d9e"
                        .to_string(),
                    target_digest: "sha256:tgt".to_string(),
                },
                ImageRecord {
                    name: "docker.io/thegrandpkizzle/mirrors@sha256:2a25".to_string(),
                    target_digest: "sha256:tgt".to_string(),
                },
            ];
            if order {
                records.reverse();
            }
            let groups = group_records_by_target(&records);
            assert_eq!(groups.len(), 1);
            assert_eq!(
                groups[0].display_ref, "docker.io/thegrandpkizzle/mirrors@sha256:2a25",
                "repo@digest ref must beat the image-ID record (order={order})"
            );
        }
    }

    /// A target known ONLY by image-ID records has no usable ref — the group
    /// is dropped rather than poisoning the chain map with a bare digest.
    #[test]
    fn group_records_drops_image_id_only_groups() {
        let records = vec![ImageRecord {
            name: "sha256:0c0da3558734bbf673448b752bb6c139cbd3ece8060c6589370280b8ba631d9e"
                .to_string(),
            target_digest: "sha256:tgt".to_string(),
        }];
        assert!(group_records_by_target(&records).is_empty());
    }

    #[test]
    fn ref_name_rank_orders_tag_over_digest_over_bare() {
        assert_eq!(ref_name_rank("docker.io/library/nginx:1.27"), 3);
        assert_eq!(ref_name_rank("docker.io/library/nginx@sha256:abc"), 2);
        assert_eq!(ref_name_rank("docker.io/library/nginx"), 1);
        assert_eq!(ref_name_rank("localhost:5000/img"), 1); // port, not tag
        assert_eq!(
            ref_name_rank("sha256:0c0da3558734bbf673448b752bb6c139cbd3ece806"),
            0
        );
    }
}
