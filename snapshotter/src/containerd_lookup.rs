// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Image-ref lookup fallback by inspecting containerd's image store via
//! `crictl` / `ctr`.
//!
//! containerd 2.x (as shipped in k3s ≥ v1.36) does not forward the
//! `containerd.io/snapshot/cri.image-ref` label to proxy-plugin snapshotters
//! at container Prepare time. To still resolve the image reference for a
//! given Nydus bootstrap blob digest we walk all images known to containerd,
//! fetch their manifests and record the
//! `containerd.io/snapshot/nydus-bootstrap` annotated layer digest →
//! image-ref mapping in a small in-memory cache.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, PoisonError};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// Acquire a lock without panicking on poisoning. A previous panic while a
/// lock was held would only have left the cache in a partially-populated
/// state; the worst case is a redundant containerd refresh, which is safe.
fn lock_cache<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

const NYDUS_BOOTSTRAP_ANNOTATION: &str = "containerd.io/snapshot/nydus-bootstrap";

#[derive(Default)]
pub struct ContainerdLookup {
    /// Cache: snapshot key digest (chainID **or** layer digest, `sha256:…`)
    /// → image ref. Both are populated so a lookup using either kind of
    /// digest succeeds.
    cache: Mutex<HashMap<String, String>>,
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the image ref for a given bootstrap layer / topmost chain
    /// digest. Returns:
    ///
    /// - `Ok(Some(image_ref))` — hit.
    /// - `Ok(None)` — refresh succeeded but no image references this digest
    ///   (genuine miss).
    /// - `Err(_)` — couldn't refresh (crictl unreachable, JSON unparsable,
    ///   etc.). Distinguishing this from a miss lets callers log loudly
    ///   when discovery is broken vs simply absent — previously we
    ///   collapsed both into `None` and a registry flake silently disabled
    ///   auto-accel cluster-wide.
    pub fn lookup(&self, bootstrap_digest: &str) -> Result<Option<String>> {
        if let Some(r) = lock_cache(&self.cache).get(bootstrap_digest) {
            return Ok(Some(r.clone()));
        }
        self.refresh()?;
        let hit = lock_cache(&self.cache).get(bootstrap_digest).cloned();
        if hit.is_none() {
            info!(
                bootstrap = %bootstrap_digest,
                "no containerd image found containing nydus bootstrap digest"
            );
        }
        Ok(hit)
    }

    fn refresh(&self) -> Result<()> {
        // Try `crictl images -o json` first, fall back to `k3s crictl`.
        let out = run_first_ok(&[
            &["crictl", "images", "-o", "json"],
            &["k3s", "crictl", "images", "-o", "json"],
        ])?;
        let parsed: CrictlImages = serde_json::from_slice(&out)?;
        let mut map: HashMap<String, String> = HashMap::new();
        for img in parsed.images {
            // Use repoDigests when available; they carry both ref and manifest digest.
            // Fallback to repoTags (no digest known, must look up via `ctr image inspect`).
            for repo_digest in &img.repo_digests {
                // Format: "name@sha256:<digest>"
                let Some((name, manifest_digest)) = repo_digest.split_once('@') else {
                    continue;
                };
                let ref_name = preferred_ref(&img.repo_tags, name);
                if let Err(e) = self.walk_manifest(manifest_digest, &ref_name, &mut map) {
                    debug!(image = %ref_name, error = %e, "walk_manifest failed");
                }
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

    fn walk_manifest(
        &self,
        digest: &str,
        image_ref: &str,
        out: &mut HashMap<String, String>,
    ) -> Result<()> {
        let bytes = run_first_ok(&[
            &["ctr", "-n", "k8s.io", "content", "get", digest],
            &["k3s", "ctr", "-n", "k8s.io", "content", "get", digest],
        ])?;
        // Try as index first (multi-arch); if no `manifests` field, treat as manifest.
        if let Ok(index) = serde_json::from_slice::<OciIndex>(&bytes)
            && !index.manifests.is_empty()
        {
            for child in index.manifests {
                if let Err(e) = self.walk_manifest(&child.digest, image_ref, out) {
                    debug!(child = %child.digest, error = %e, "child manifest fetch failed");
                }
            }
            return Ok(());
        }
        let manifest: OciManifest = serde_json::from_slice(&bytes)?;
        // Locate any nydus-bootstrap layer index (typically the last layer).
        // Standard OCI images have none; the cache still needs to map their
        // topmost chainID to image-ref so the auto-accel capture/discovery
        // path in grpc::prepare can resolve image-ref when containerd's CRI
        // plugin doesn't pass the `cri.image-ref` label (2.x default).
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
                // Insert by layer digest (works if containerd uses layer digest).
                out.insert(layer.digest.clone(), image_ref.to_string());
                bootstrap_indices.push(i);
            }
        }
        // Compute chainIDs from the image config's diff_ids. We register the
        // topmost chain_id unconditionally (for auto-accel lookup) and any
        // bootstrap-layer chain_ids (for nydus-meta lookup).
        let Some(cfg_desc) = manifest.config.as_ref() else {
            return Ok(());
        };
        // Config fetch + parse failure used to silently `return Ok(())`,
        // which on a refresh sweep skipped the affected image without ever
        // notifying the caller and (worse) baked the missing entry into
        // the cache's "first writer wins" via `or_insert`. Now we bubble
        // up — `refresh()` can decide whether to keep the partial map or
        // bail; the chain insert at the producer side is the same.
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
}

/// Pure registration step factored out of `walk_manifest` so unit tests
/// can pin the chainID rules (topmost-for-any-image, bootstrap-layer-for-
/// nydus) without shelling out to ctr/crictl.
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
    // both capture and discovery are dead. The 9bffd0f1 commit added
    // this; the test below pins that the cache entry exists for an image
    // with no bootstrap-annotated layer.
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

impl ContainerdLookup {
    /// Forward direction: resolve an image reference to its manifest digest
    /// and ordered gzip layer list (lower→upper), with each layer's on-disk
    /// path in containerd's content store. Returns `None` if the image isn't
    /// known to crictl, has no compatible architecture in a multi-arch index,
    /// or carries no readable gzip layers.
    ///
    /// This is on-demand (not cached); the conversion path needs a single
    /// resolution per image and the call cost is dominated by `ctr content
    /// get` for the manifest+config blobs, which is cheap.
    pub fn manifest_info(
        &self,
        image_ref: &str,
        content_root: &std::path::Path,
    ) -> Result<ManifestInfo> {
        // Walk crictl images to find the manifest digest for this ref.
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
            // Walk the manifest (resolving indices on multi-arch) for this arch.
            let (final_digest, gzip_layers) = resolve_gzip_layers(&manifest_digest, content_root)?;
            return Ok(ManifestInfo {
                manifest_digest: final_digest,
                layers: gzip_layers,
            });
        }
        anyhow::bail!(
            "image {image_ref} not found in crictl images output; \
             make sure it's been pulled at least once"
        )
    }
}

/// Resolve an index/manifest reference to (manifest_digest, gzip_layers) for
/// the current host's architecture. For a single-manifest digest this is a
/// pass-through; for a multi-arch index we pick the matching child by GOARCH.
fn resolve_gzip_layers(
    digest: &str,
    content_root: &std::path::Path,
) -> Result<(String, Vec<crate::local_accel::GzipLayer>)> {
    let bytes = run_first_ok(&[
        &["ctr", "-n", "k8s.io", "content", "get", digest],
        &["k3s", "ctr", "-n", "k8s.io", "content", "get", digest],
    ])?;
    // Multi-arch index? Pick the child matching this host's arch.
    if let Ok(index) = serde_json::from_slice::<OciIndexWithPlatforms>(&bytes)
        && !index.manifests.is_empty()
    {
        let host_arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        let host_os = std::env::consts::OS;
        for child in &index.manifests {
            let arch_match = child
                .platform
                .as_ref()
                .map(|p| p.architecture == host_arch && p.os == host_os)
                .unwrap_or(false);
            if arch_match {
                return resolve_gzip_layers(&child.digest, content_root);
            }
        }
        anyhow::bail!("no manifest in index {digest} matches host {host_os}/{host_arch}");
    }
    // Plain manifest.
    let manifest: OciManifest = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parse manifest {digest}: {e}"))?;
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for layer in manifest.layers {
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
            anyhow::bail!(
                "layer {} not present at {} (content store out of sync?)",
                layer.digest,
                path.display()
            );
        }
        layers.push(crate::local_accel::GzipLayer {
            digest: layer.digest,
            path,
        });
    }
    if layers.is_empty() {
        anyhow::bail!("manifest {digest} has no gzip layers");
    }
    Ok((digest.to_string(), layers))
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
                last_err = Some(format!("{} not runnable: {}", prog, e));
            }
        }
    }
    bail!(last_err.unwrap_or_else(|| "no candidate commands".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_containerd_chain_ids() {
        let diff_ids = vec![
            "sha256:8eac19f9e87977480de84b7569cbd6801c42129116a797685e10bb5b054f99a7".to_string(),
            "sha256:800fc873f06d73e99c37b6f1b37a12029cad46f0ef7206ed2c384ccb0a76ae90".to_string(),
            "sha256:34497c91e0bd10466904a6ed6c8607803508365530f92351733772944b375ffe".to_string(),
            "sha256:55bf81f67da16800c45a5795e7509ddb79894f74c33bad90e2943120bc0496de".to_string(),
            "sha256:fe976eff9fec34e507a3f60609984d25687b2d867e2abf9dcc6d5a2955cc125c".to_string(),
        ];
        let ids = chain_ids(&diff_ids);
        assert_eq!(ids.first(), diff_ids.first());
        assert_eq!(
            ids.last().map(String::as_str),
            Some("sha256:4a847a1679c3b9696f37e18ee02f012e19cdadb36192e56f3200c8a58dcbd640")
        );
    }

    #[test]
    fn preferred_ref_uses_tag_when_available() {
        let tags = vec!["docker.io/example/app:v1".to_string()];
        assert_eq!(preferred_ref(&tags, "docker.io/example/app"), tags[0]);
        assert_eq!(
            preferred_ref(&[], "docker.io/example/app"),
            "docker.io/example/app"
        );
    }

    #[test]
    fn chain_ids_empty_input_returns_empty() {
        assert!(chain_ids(&[]).is_empty());
    }

    #[test]
    fn chain_ids_single_layer_equals_diff_id() {
        let d = "sha256:aaaa".to_string();
        let out = chain_ids(std::slice::from_ref(&d));
        assert_eq!(out, vec![d]);
    }

    #[test]
    fn lookup_recovers_from_poisoned_mutex() {
        let lookup = ContainerdLookup::new();
        // Deliberately poison the cache mutex.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = lookup.cache.lock().unwrap();
            panic!("intentional poison");
        }));
        assert!(result.is_err(), "panic should have propagated");
        assert!(lookup.cache.is_poisoned(), "mutex should be poisoned");
        // The lookup itself must not panic. It may return None when no
        // `crictl`/`ctr` binary is available, but it must succeed in
        // reaching the get-on-cache path despite the poisoned mutex.
        let _ = lookup.lookup("sha256:does-not-exist");
    }

    /// Standard OCI images (no nydus-bootstrap annotated layer) MUST
    /// still register their topmost chainID against the image-ref —
    /// otherwise the prepare path can't resolve `image_ref` from the
    /// snapshot's parent chain when containerd's CRI plugin omits the
    /// `cri.image-ref` label (which it does on every container rootfs
    /// prepare in 2.x). Commit 9bffd0f1 added the unconditional topmost
    /// registration; this test pins that behaviour so a future refactor
    /// can't quietly drop it.
    #[test]
    fn register_chain_ids_writes_topmost_for_standard_oci_image() {
        let mut out = HashMap::new();
        let diff_ids = vec![
            "sha256:8eac19f9e87977480de84b7569cbd6801c42129116a797685e10bb5b054f99a7".to_string(),
            "sha256:800fc873f06d73e99c37b6f1b37a12029cad46f0ef7206ed2c384ccb0a76ae90".to_string(),
        ];
        // No bootstrap layers — standard OCI (nginx, postgres, etc.).
        register_chain_ids("docker.io/library/nginx", &diff_ids, &[], &mut out);
        let chain_ids = chain_ids(&diff_ids);
        let topmost = chain_ids.last().unwrap();
        assert_eq!(
            out.get(topmost).map(String::as_str),
            Some("docker.io/library/nginx"),
            "topmost chainID must map to image ref even when image has NO nydus-bootstrap layer"
        );
    }

    #[test]
    fn register_chain_ids_writes_bootstrap_layer_entries_when_present() {
        let mut out = HashMap::new();
        let diff_ids = vec![
            "sha256:layer-a".to_string(),
            "sha256:layer-b".to_string(),
            "sha256:layer-c-nydus-bootstrap".to_string(),
        ];
        // Layer index 2 carries the nydus-bootstrap annotation.
        register_chain_ids("registry.local/img:nydus", &diff_ids, &[2], &mut out);
        let chain_ids = chain_ids(&diff_ids);
        let topmost = chain_ids.last().unwrap();
        let bootstrap = chain_ids.get(2).unwrap();
        // The bootstrap layer IS the topmost in this example, so the
        // entry is registered once; the assertions verify the value is
        // the correct image ref via both code paths.
        assert_eq!(
            out.get(topmost).map(String::as_str),
            Some("registry.local/img:nydus")
        );
        assert_eq!(
            out.get(bootstrap).map(String::as_str),
            Some("registry.local/img:nydus")
        );
    }

    #[test]
    fn register_chain_ids_skips_empty_diff_id_list() {
        // Edge: corrupt or missing image config => empty diff_ids. Don't
        // register a phantom entry.
        let mut out = HashMap::new();
        register_chain_ids("docker.io/library/nginx", &[], &[], &mut out);
        assert!(out.is_empty());
    }
}
