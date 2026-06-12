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

use crate::content_store::ContentStoreClient;

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
struct OciIndex {
    #[serde(default)]
    manifests: Vec<OciDescriptor>,
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
        match &self.content_store {
            Some(cs) => self.refresh_via_grpc(cs, &mut map).await?,
            None => {
                // CLI fallback: spawning crictl/ctr is slow and blocking —
                // keep it off the gRPC runtime.
                let walked = blocking::unblock(walk_images_via_cli).await?;
                map = walked;
            }
        }
        let count = map.len();
        let mut cache = lock_cache(&self.cache);
        for (k, v) in map {
            cache.entry(k).or_insert(v);
        }
        info!(
            entries = count,
            total = cache.len(),
            "containerd image-ref cache refreshed"
        );
        Ok(())
    }

    async fn refresh_via_grpc(
        &self,
        cs: &ContentStoreClient,
        map: &mut HashMap<String, String>,
    ) -> Result<()> {
        let records = cs.images_list().await.context("containerd Images.List")?;
        for group in group_records_by_target(&records) {
            if let Err(e) = walk_manifest_via_grpc(cs, &group.target, &group.display_ref, map).await
            {
                debug!(image = %group.display_ref, error = %e, "walk_manifest failed");
            }
        }
        Ok(())
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

/// Group image records by target digest, preferring a tag-form name
/// (`name:tag`) over a digest-form one (`name@sha256:...`) as the display
/// ref — mirrors the legacy `preferred_ref` (crictl repoTags first).
fn group_records_by_target(records: &[ImageRecord]) -> Vec<RecordGroup> {
    let mut by_target: HashMap<&str, &str> = HashMap::new();
    for record in records {
        let entry = by_target.entry(record.target_digest.as_str());
        match entry {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(record.name.as_str());
            }
            std::collections::hash_map::Entry::Occupied(mut o) => {
                let current_is_digest_form = o.get().contains('@');
                let new_is_tag_form = !record.name.contains('@');
                if current_is_digest_form && new_is_tag_form {
                    o.insert(record.name.as_str());
                }
            }
        }
    }
    by_target
        .into_iter()
        .map(|(target, display)| RecordGroup {
            target: target.to_string(),
            display_ref: display.to_string(),
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
    if let Ok(index) = serde_json::from_slice::<OciIndex>(&bytes)
        && !index.manifests.is_empty()
    {
        for child in index.manifests {
            if let Err(e) =
                Box::pin(walk_manifest_via_grpc(cs, &child.digest, image_ref, out)).await
            {
                debug!(child = %child.digest, error = %e, "child manifest fetch failed");
            }
        }
        return Ok(());
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
    /// uses this as the `containerd.io/gc.ref.content.subject` label so
    /// containerd's GC keeps the sidecar alive as long as the original
    /// manifest exists.
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
    let bytes = cs
        .fetch_bytes(digest)
        .await
        .with_context(|| format!("fetch manifest {digest}"))?;
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
    let host_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let host_os = std::env::consts::OS;
    index
        .manifests
        .iter()
        .find(|child| {
            child
                .platform
                .as_ref()
                .map(|p| p.architecture == host_arch && p.os == host_os)
                .unwrap_or(false)
        })
        .map(|child| child.digest.clone())
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
    architecture: String,
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

fn walk_images_via_cli() -> Result<HashMap<String, String>> {
    let out = run_first_ok(&[
        &["crictl", "images", "-o", "json"],
        &["k3s", "crictl", "images", "-o", "json"],
    ])?;
    let parsed: CrictlImages = serde_json::from_slice(&out)?;
    let mut map: HashMap<String, String> = HashMap::new();
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
                debug!(image = %ref_name, error = %e, "walk_manifest failed");
            }
        }
    }
    Ok(map)
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
    if let Ok(index) = serde_json::from_slice::<OciIndex>(&bytes)
        && !index.manifests.is_empty()
    {
        for child in index.manifests {
            if let Err(e) = walk_manifest_via_cli(&child.digest, image_ref, out) {
                debug!(child = %child.digest, error = %e, "child manifest fetch failed");
            }
        }
        return Ok(());
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
        if matched_manifest.is_none() {
            continue;
        }
        let manifest_digest = matched_manifest.unwrap();
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
}
