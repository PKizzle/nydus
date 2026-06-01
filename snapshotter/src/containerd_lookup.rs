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

use anyhow::{Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

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

    /// Look up the image ref for a given bootstrap layer digest. Uses an
    /// in-memory cache; on miss, refreshes by walking containerd's image
    /// store.
    pub fn lookup(&self, bootstrap_digest: &str) -> Option<String> {
        if let Some(r) = lock_cache(&self.cache).get(bootstrap_digest) {
            return Some(r.clone());
        }
        if let Err(e) = self.refresh() {
            warn!(error = %e, "containerd image-ref refresh failed");
            return None;
        }
        let hit = lock_cache(&self.cache).get(bootstrap_digest).cloned();
        if hit.is_none() {
            info!(
                bootstrap = %bootstrap_digest,
                "no containerd image found containing nydus bootstrap digest"
            );
        }
        hit
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
        if let Ok(index) = serde_json::from_slice::<OciIndex>(&bytes) {
            if !index.manifests.is_empty() {
                for child in index.manifests {
                    if let Err(e) = self.walk_manifest(&child.digest, image_ref, out) {
                        debug!(child = %child.digest, error = %e, "child manifest fetch failed");
                    }
                }
                return Ok(());
            }
        }
        let manifest: OciManifest = serde_json::from_slice(&bytes)?;
        // Locate any nydus-bootstrap layer index (typically the last layer).
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
        if bootstrap_indices.is_empty() {
            return Ok(());
        }
        // Compute chainIDs from image config diff_ids and insert under each
        // chainID up to and including any bootstrap layer. The active
        // snapshot key uses the chainID of all stacked layers.
        let Some(cfg_desc) = manifest.config.as_ref() else {
            return Ok(());
        };
        let cfg_bytes = match run_first_ok(&[
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
        ]) {
            Ok(b) => b,
            Err(e) => {
                debug!(image = %image_ref, error = %e, "image config fetch failed");
                return Ok(());
            }
        };
        let cfg: OciImageConfig = match serde_json::from_slice(&cfg_bytes) {
            Ok(c) => c,
            Err(e) => {
                debug!(image = %image_ref, error = %e, "image config parse failed");
                return Ok(());
            }
        };
        let chain_ids = chain_ids(&cfg.rootfs.diff_ids);
        for &i in &bootstrap_indices {
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
        Ok(())
    }
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
}
