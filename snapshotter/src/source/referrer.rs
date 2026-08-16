// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Referrer-based image source detection.
//!
//! Inspects OCI image manifests or OCI referrer/index descriptors to determine
//! whether an image is a Nydus-optimized image and how to serve it.
//!
//! Registry access rides the shared [`registry_client::RegistryClient`] (the
//! same bearer-auth OCI distribution client nydusify uses): resolution asks
//! the **native OCI 1.1 referrers API first**
//! (`GET /v2/<repo>/referrers/<digest>`) and falls back to the
//! `sha256-<subject-hex>` **fallback tag** when the registry lacks the API
//! ([`RegistryError::ReferrersUnsupported`]) or has nothing indexed there.
//! Classification stays entirely client-side and keeps the hard bootstrap
//! selection rules (annotation first, bootstrap media type second — never a
//! loose "contains nydus" match, which once selected data blobs).
//!
//! `RegistryClient` is `!Send` (cyper/compio, Rc-based), so it is constructed
//! and used entirely inside the `blocking::unblock` + thread-local compio
//! runtime hops (`detect_referrer_blocking` /
//! `materialize_bootstrap_blocking`), mirroring `peer_mirror.rs`.

use crate::cache::parse_duration;
use crate::config::SnapshotterConfig;
use crate::daemon::auth::resolve_auth;
use crate::daemon::image_ref::{ImageRef, parse_image_ref};
use anyhow::{Context, Result, anyhow, bail};
use registry_client::{RegistryClient, RegistryClientOptions, RegistryError};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tracing::{debug, info, warn};

const DEFAULT_CACHE_CAPACITY: usize = 500;
const NYDUS_BOOTSTRAP_ANNOTATION: &str = "containerd.io/snapshot/nydus-bootstrap";
const NYDUS_FS_DRIVER_HINT: &str = "containerd.io/snapshot/nydus-fs-driver";

/// Detected image type from referrer inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageType {
    /// Standard Nydus RAFS image with a bootstrap referrer.
    NydusRafs,
    /// OCI block device image (EROFS-only, no nydusd needed).
    OciBlockDevice,
    /// Standard OCI image with no Nydus optimization detected.
    StandardOci,
}

/// Result of referrer detection.
#[derive(Clone, Debug)]
pub struct ReferrerInfo {
    pub image_type: ImageType,
    pub bootstrap_digest: Option<String>,
    pub fs_driver_hint: Option<String>,
}

/// Small bounded LRU cache for referrer detection results.
#[derive(Debug)]
pub struct ReferrerCache {
    capacity: usize,
    map: HashMap<String, ReferrerInfo>,
    order: VecDeque<String>,
}

impl ReferrerCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn get(&mut self, image_ref: &str) -> Option<ReferrerInfo> {
        let value = self.map.get(image_ref).cloned()?;
        self.touch(image_ref);
        Some(value)
    }

    pub fn insert(&mut self, image_ref: String, info: ReferrerInfo) {
        if self.map.contains_key(&image_ref) {
            self.map.insert(image_ref.clone(), info);
            self.touch(&image_ref);
            return;
        }
        while self.map.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.order.push_back(image_ref.clone());
        self.map.insert(image_ref, info);
    }

    fn touch(&mut self, image_ref: &str) {
        self.order.retain(|item| item != image_ref);
        self.order.push_back(image_ref.to_string());
    }
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
}

#[derive(Deserialize)]
struct OciDescriptor {
    digest: String,
    #[serde(default, rename = "mediaType")]
    media_type: String,
    #[serde(default, rename = "artifactType")]
    artifact_type: String,
    #[serde(default)]
    annotations: HashMap<String, String>,
}

static REFERRER_CACHE: OnceLock<Mutex<ReferrerCache>> = OnceLock::new();

thread_local! {
    /// Per-thread compio runtime used by [`detect_referrer_blocking`] to drive
    /// cyper from inside `blocking::unblock`. cyper's `Client` is `!Send`
    /// (Rc-based, targets the compio current-thread runtime) and its HTTPS
    /// plumbing needs `Runtime::current()` at build time plus a `block_on` to
    /// run requests — the same threading model `peer_mirror.rs` uses.
    static REFERRER_HTTP_RUNTIME: compio::runtime::Runtime = compio::runtime::Runtime::new()
        .expect("referrer: failed to create compio HTTP runtime");
}

/// Run referrer detection off the caller's (gRPC) runtime.
///
/// cyper's `Client` is `!Send`, but the snapshotter trait requires `Send`
/// futures, so all referrer HTTP runs inside `blocking::unblock` on a
/// thread-local compio runtime (mirroring `peer_mirror.rs`). Only `Send`
/// state (the owned `image_ref` + cloned `config`) crosses the boundary; the
/// returned [`ReferrerInfo`] is owned and `Send`. Detection results are cached
/// in the module-global LRU (both Nydus hits and StandardOci), so a given image
/// ref costs at most one registry round-trip cluster-lifetime, not per-Prepare.
pub async fn detect_referrer_blocking(
    image_ref: &str,
    config: &SnapshotterConfig,
) -> Result<ReferrerInfo> {
    let image_ref = image_ref.to_string();
    let config = config.clone();
    blocking::unblock(move || {
        REFERRER_HTTP_RUNTIME
            .with(|rt| rt.block_on(detect_referrer_with_config(&image_ref, &config)))
    })
    .await
}

/// Inspect an image reference for Nydus referrer descriptors.
pub async fn detect_referrer(image_ref: &str) -> Result<ReferrerInfo> {
    detect_referrer_with_config(image_ref, &SnapshotterConfig::default()).await
}

/// Inspect an image reference for Nydus referrer descriptors using runtime
/// snapshotter configuration and auth.
pub async fn detect_referrer_with_config(
    image_ref: &str,
    config: &SnapshotterConfig,
) -> Result<ReferrerInfo> {
    if let Some(cached) = global_cache()
        .lock()
        .ok()
        .and_then(|mut c| c.get(image_ref))
    {
        return Ok(cached);
    }
    // Only *resolved* outcomes are cached (the "one lookup per image
    // cluster-lifetime" contract): a genuine nydus hit, and a genuine "no
    // referrer artifact exists" miss. A transient registry error (network
    // blip, registry restart, DNS hiccup at pod start) must NOT be cached as
    // StandardOci — doing so permanently disabled referrer serving for the
    // image until the process restarted. On error we return the StandardOci
    // fallback (so the pod still schedules via overlay) but leave the cache
    // empty so the next prepare retries.
    match detect(image_ref, config).await {
        Ok(info) => {
            let info = info.unwrap_or_else(standard_oci);
            if let Ok(mut cache) = global_cache().lock() {
                cache.insert(image_ref.to_string(), info.clone());
            }
            Ok(info)
        }
        Err(e) => {
            debug!(%image_ref, error = %e, "referrer registry query failed; using StandardOci fallback (not cached, will retry)");
            Ok(standard_oci())
        }
    }
}

/// Build [`RegistryClientOptions`] from `[backends.registry]` plus a resolved
/// runtime-auth payload.
///
/// * `plain_http` — HTTPS by default (secure); `[backends.registry]
///   plain_http = true` opts the registry into cleartext HTTP, mirroring the
///   same opt-in the storage backend honors. SECURITY: plain HTTP disables
///   transport encryption AND server authentication, so an on-path attacker
///   can read and *tamper with* referrer manifests and bootstrap blobs.
///   Because the artifact manifest — which declares the bootstrap's expected
///   digest — is fetched over the same cleartext channel, B4b's bootstrap
///   digest verification does NOT protect against a MITM here: they control
///   both the declared digest and the served bytes, so a forged bootstrap
///   verifies fine. Same exposure as any plain-HTTP image pull; only enable
///   it for registries on a trusted network (loopback, air-gapped, LAN).
/// * TLS trust mirrors the storage blob backend: `skip_verify` wins, then
///   `ca_cert_files` extends the platform store, then the default verifier.
///   Without the middle branch a private-CA registry could serve blobs but
///   silently fail referrer detection.
/// * `use_docker_config` is force-disabled: the snapshotter's auth policy
///   (`daemon/auth.rs`) is runtime-injected credentials only — it never reads
///   docker `config.json` or Kubernetes Secret files from disk. `raw_auth`
///   carries the runtime store's docker-style base64 payload instead.
fn client_options_from_config(
    config: &SnapshotterConfig,
    raw_auth: Option<String>,
) -> RegistryClientOptions {
    let registry = config.backends.registry.as_ref();
    let timeout = registry
        .and_then(|cfg| parse_duration(&cfg.request_timeout).ok())
        .unwrap_or_else(|| Duration::from_secs(30));
    RegistryClientOptions {
        plain_http: registry.map(|cfg| cfg.plain_http).unwrap_or(false),
        insecure_tls: registry.map(|cfg| cfg.skip_verify).unwrap_or(false),
        ca_cert_files: registry
            .map(|cfg| cfg.ca_cert_files.iter().map(PathBuf::from).collect())
            .unwrap_or_default(),
        timeout: Some(timeout),
        raw_auth,
        use_docker_config: false,
        ..RegistryClientOptions::default()
    }
}

/// Construct the shared OCI distribution client for `image`'s registry host.
///
/// The returned [`RegistryClient`] is `!Send` (cyper/compio) and its TLS
/// plumbing needs `Runtime::current()` at build time, so this must run on a
/// thread that owns a compio runtime — in production, inside the
/// `REFERRER_HTTP_RUNTIME.block_on` of the `*_blocking` wrappers.
fn build_registry_client(image: &ImageRef, config: &SnapshotterConfig) -> Result<RegistryClient> {
    let auth = resolve_auth(config, image);
    RegistryClient::new(&image.api_host, client_options_from_config(config, auth))
        .context("build referrer registry client")
}

/// Referrer resolution proper: resolve the subject digest, then consult the
/// **native OCI 1.1 referrers API first** and the `sha256-<subject-hex>`
/// fallback tag second.
async fn detect(image_ref: &str, config: &SnapshotterConfig) -> Result<Option<ReferrerInfo>> {
    let parsed = parse_image_ref(image_ref).context("invalid image reference")?;
    let client = build_registry_client(&parsed, config)?;
    let repo = parsed.repo.as_str();

    // Subject digest: an explicit `@sha256:...` wins; else resolve the tag by
    // fetching the top-level (index or image) manifest. `get_manifest`
    // computes the digest locally from the body bytes, so registries that
    // omit the optional Docker-Content-Digest header resolve correctly too
    // (they once classified every image as StandardOci).
    let mut top_bytes: Option<Vec<u8>> = None;
    let digest = if let Some(digest) = parsed.digest.clone() {
        // kubelet resolves tags to digests before CRI ever pulls, so production image refs
        // arrive digest-pinned -- and that digest names the top-level object (the dual index
        // itself, verified against a live pull). Without fetching it here, dual-manifest
        // detection would only ever fire for tag-form refs (ctr, tests), never for a pod.
        match client.get_manifest(repo, &digest).await {
            Ok(fetched) => top_bytes = Some(fetched.bytes),
            Err(e) => {
                debug!(%digest, error = %e, "could not fetch pinned top-level manifest; skipping dual-index detection");
            }
        }
        digest
    } else if let Some(tag) = parsed.tag.as_deref() {
        match client.get_manifest(repo, tag).await {
            Ok(fetched) => {
                let digest = fetched.digest;
                top_bytes = Some(fetched.bytes);
                digest
            }
            Err(RegistryError::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e).context("resolve subject manifest digest"),
        }
    } else {
        return Ok(None);
    };

    // (0) Dual-manifest index (nydusify `--attach-oci-manifest` / Go `merge_manifest`): the
    // nydus manifest may be a sibling entry in the image's own index, marked by artifactType
    // or the legacy os.features. More authoritative than any referrer -- it is part of the
    // image -- and this is the only place it gets noticed: containerd resolves the OCI half
    // (first platform match), so Prepare alone would ride the plain-OCI path and the
    // pre-built nydus artifact would go unused.
    if let Some(bytes) = top_bytes.as_deref()
        && let Some(info) = classify_dual_index(bytes)
    {
        return Ok(Some(info));
    }

    // (1) Native referrers API. Deliberately NO server-side artifactType
    // filter: the snapshotter recognizes both nydus artifacts (nydusify's
    // `application/vnd.oci.image.layer.nydus.blob.v1` artifactType) and
    // erofs/blockdev artifacts, and a server-side filter would hide the
    // latter. Classification is client-side regardless — the spec lets
    // servers ignore the filter, so a local pass is mandatory anyway.
    match client.get_referrers(repo, &digest, None).await {
        Ok(index) => {
            let info = classify_referrers_index(&index)?;
            if info.image_type != ImageType::StandardOci {
                return Ok(Some(info));
            }
        }
        Err(RegistryError::ReferrersUnsupported) => {
            debug!(image = %image_ref, "registry lacks the OCI 1.1 referrers API; trying fallback tag");
        }
        Err(e) => {
            // A broken referrers endpoint must not kill detection while the
            // fallback tag can still answer (same stance as the pre-
            // convergence bespoke client).
            warn!(image = %image_ref, error = format!("{e:#}"), "referrers API query failed; trying fallback tag");
        }
    }

    // (2) Fallback tag (`sha256-<subject-hex>`), the pre-1.1 convention that
    // nydusify publishes alongside the digest push.
    match client
        .get_manifest(repo, &fallback_referrers_tag(&digest))
        .await
    {
        Ok(fetched) => {
            let info = detect_from_oci_json(&fetched.bytes)?;
            if info.image_type != ImageType::StandardOci {
                return Ok(Some(info));
            }
        }
        // Absent tag or any other HTTP status: no fallback artifact
        // (matching the old client's "any non-success means absent" stance).
        Err(RegistryError::NotFound { .. }) => {}
        Err(RegistryError::Http { status, .. }) => {
            debug!(image = %image_ref, status, "fallback-tag lookup returned non-success; treating as absent");
        }
        // Transport-level failures propagate so the caller's don't-cache-
        // transient-errors contract holds and the next Prepare retries.
        Err(e) => return Err(e).context("fetch referrers fallback tag"),
    }

    Ok(None)
}

/// Classify a typed referrers index by funneling it through
/// [`detect_from_oci_json`] — the single classification code path (bootstrap
/// annotation first, media types second), so the referrers-API and
/// fallback-tag branches can never drift apart.
/// Spot a nydus manifest published as a sibling entry of the image's own index.
///
/// Only entries for this node's platform count: a dual index for amd64+arm64 carries one
/// nydus entry per converted platform, and serving another architecture's bootstrap would
/// produce a rootfs of the wrong machine. The returned `bootstrap_digest` is the nydus
/// MANIFEST digest -- `materialize_bootstrap` already probes manifests and walks to their
/// nydus-bootstrap layer.
///
/// A marked entry carrying NO platform is deliberately **not** matched. Such an entry can
/// only come from a foreign tool (nydusify always writes a platform, and the legacy
/// `os.features` marker lives inside `platform` so a legacy-marked entry necessarily has
/// one), and nothing downstream would catch the mismatch: `materialize_bootstrap` only
/// verifies the digest, the EROFS mount succeeds, and the wrong architecture surfaces as
/// an exec-format error inside the container. Skipping it just falls through to the
/// referrers API and the fallback tag.
fn classify_dual_index(index_bytes: &[u8]) -> Option<ReferrerInfo> {
    let index = serde_json::from_slice::<registry_client::Index>(index_bytes).ok()?;
    let host = registry_client::Platform {
        architecture: registry_client::host_go_arch().to_string(),
        os: "linux".to_string(),
        ..registry_client::Platform::default()
    };
    let entry = index.manifests.iter().find(|m| {
        registry_client::is_nydus_entry(m) && m.platform.as_ref().is_some_and(|p| p.matches(&host))
    })?;
    debug!(nydus_manifest = %entry.digest, "found nydus sibling manifest in the image's own index");
    Some(ReferrerInfo {
        image_type: ImageType::NydusRafs,
        bootstrap_digest: Some(entry.digest.clone()),
        fs_driver_hint: None,
    })
}

fn classify_referrers_index(index: &registry_client::Index) -> Result<ReferrerInfo> {
    let payload = serde_json::to_vec(index).context("serialize referrers index for detection")?;
    detect_from_oci_json(&payload)
}

/// Classify an OCI referrer response or index/manifest JSON payload. This is
/// used as the fallback when registries do not expose the referrers API but do
/// expose an index manifest carrying Nydus descriptors.
pub fn detect_from_oci_json(payload: &[u8]) -> Result<ReferrerInfo> {
    if let Ok(index) = serde_json::from_slice::<OciIndex>(payload)
        && let Some(info) = index.manifests.iter().find_map(classify_descriptor)
    {
        return Ok(info);
    }
    if let Ok(manifest) = serde_json::from_slice::<OciManifest>(payload) {
        // A `layers` array is the artifact MANIFEST itself (the fallback-tag
        // path fetches it directly). Its layers list data blobs
        // (`...layer.nydus.blob.v1`) BEFORE the bootstrap by convention, and
        // data-blob media types also contain "nydus" — so the loose
        // `classify_descriptor` predicate must NOT be used here: it would
        // return the first data blob's digest as the "bootstrap" and the
        // serving path would mount data bytes as RAFS metadata. Target the
        // bootstrap layer specifically (annotation first, then a "bootstrap"
        // media type), exactly like `select_nydus_bootstrap_layer`.
        if let Some(boot) = bootstrap_layer_of(&manifest.layers) {
            return Ok(ReferrerInfo {
                image_type: ImageType::NydusRafs,
                bootstrap_digest: Some(boot.digest.clone()),
                fs_driver_hint: boot.annotations.get(NYDUS_FS_DRIVER_HINT).cloned(),
            });
        }
        // EROFS/blockdev artifacts have no bootstrap layer; they are still
        // recognized by their distinctive media types (never "nydus.blob").
        if let Some(info) = manifest
            .layers
            .iter()
            .find(|desc| {
                let media = format!("{} {}", desc.media_type, desc.artifact_type);
                media.contains("erofs") || media.contains("blockdev")
            })
            .and_then(classify_descriptor)
        {
            return Ok(info);
        }
        // Deliberately NO loose "contains nydus/rafs" fallback for layers: a
        // manifest with nydus data blobs but no identifiable bootstrap is not
        // servable — StandardOci (plain overlay) is the safe answer.
    }
    Ok(standard_oci())
}

/// Priority-select the nydus bootstrap layer from a manifest's `layers`:
///   1. a layer annotated `containerd.io/snapshot/nydus-bootstrap == "true"`
///      (authoritative — nydusify and the Go tooling both set it);
///   2. else a layer whose mediaType/artifactType contains "bootstrap"
///      (`...bootstrap.nydus...` is distinct from `...layer.nydus.blob...`).
///
/// Returns `None` when no layer qualifies. Callers must treat that as "not a
/// servable nydus artifact" and must NEVER fall back to a loose
/// "contains nydus" match over layers — data blobs match that too, and the
/// artifact convention orders them before the bootstrap.
fn bootstrap_layer_of(layers: &[OciDescriptor]) -> Option<&OciDescriptor> {
    let annotated = layers.iter().find(|desc| {
        desc.annotations
            .get(NYDUS_BOOTSTRAP_ANNOTATION)
            .map(|v| v == "true")
            .unwrap_or(false)
    });
    annotated.or_else(|| {
        layers.iter().find(|desc| {
            format!("{} {}", desc.media_type, desc.artifact_type).contains("bootstrap")
        })
    })
}

fn classify_descriptor(desc: &OciDescriptor) -> Option<ReferrerInfo> {
    let media_or_artifact = format!("{} {}", desc.media_type, desc.artifact_type);
    let bootstrap = desc
        .annotations
        .get(NYDUS_BOOTSTRAP_ANNOTATION)
        .map(|v| v == "true")
        .unwrap_or(false)
        || media_or_artifact.contains("nydus")
        || media_or_artifact.contains("rafs");
    if bootstrap {
        return Some(ReferrerInfo {
            image_type: ImageType::NydusRafs,
            bootstrap_digest: Some(desc.digest.clone()),
            fs_driver_hint: desc.annotations.get(NYDUS_FS_DRIVER_HINT).cloned(),
        });
    }
    if media_or_artifact.contains("erofs") || media_or_artifact.contains("blockdev") {
        return Some(ReferrerInfo {
            image_type: ImageType::OciBlockDevice,
            bootstrap_digest: None,
            fs_driver_hint: desc
                .annotations
                .get(NYDUS_FS_DRIVER_HINT)
                .cloned()
                .or_else(|| Some("blockdev".to_string())),
        });
    }
    None
}

fn standard_oci() -> ReferrerInfo {
    ReferrerInfo {
        image_type: ImageType::StandardOci,
        bootstrap_digest: None,
        fs_driver_hint: None,
    }
}

/// If `manifest_bytes` parses as an OCI manifest with a non-empty `layers`
/// array, return the digest of its nydus **bootstrap** layer. Returns `None`
/// when the bytes are not a manifest with layers (e.g. a raw bootstrap blob) or
/// when no layer qualifies as the bootstrap, so the caller falls back to the
/// direct-blob path.
///
/// This deliberately does NOT reuse `classify_descriptor`'s loose "contains
/// nydus/rafs" predicate: a published nydus artifact lists its **data-blob**
/// layers with mediaType `application/vnd.oci.image.layer.nydus.blob.v1`, which
/// also contains "nydus". Selecting the first such match would pick a data blob
/// (typically listed before the bootstrap) and hand `ensure_instance` a blob
/// that is not a valid RAFS bootstrap. Instead we target the bootstrap layer
/// specifically, preferring the reliable annotation over a media-type match:
///   1. a layer annotated `containerd.io/snapshot/nydus-bootstrap == "true"`;
///   2. else a layer whose mediaType/artifactType contains "bootstrap"
///      (nydus bootstrap layers use a `...bootstrap.nydus...` media type,
///      distinct from `...layer.nydus.blob...` data blobs).
fn select_nydus_bootstrap_layer(manifest_bytes: &[u8]) -> Option<String> {
    let manifest = serde_json::from_slice::<OciManifest>(manifest_bytes).ok()?;
    // Shared priority selection (annotation → bootstrap media type) with
    // `detect_from_oci_json`'s layers branch, so the two consume-side paths
    // (initial detection via the fallback tag, and the materialize-time
    // artifact-manifest walk) can never drift apart again.
    bootstrap_layer_of(&manifest.layers).map(|desc| desc.digest.clone())
}

/// Verify `bytes` hash to `expected` (a `sha256:<hex>` digest). Security-
/// critical: a bootstrap that fails this is never written or mounted.
fn verify_bootstrap_digest(bytes: &[u8], expected: &str) -> Result<()> {
    let want = expected.strip_prefix("sha256:").ok_or_else(|| {
        anyhow!("unsupported bootstrap digest {expected}; only sha256 is supported")
    })?;
    let got = hex::encode(Sha256::digest(bytes));
    if !got.eq_ignore_ascii_case(want) {
        bail!("bootstrap digest mismatch: expected {expected}, computed sha256:{got}");
    }
    Ok(())
}

/// Digest-named on-disk path for a materialized bootstrap.
fn bootstrap_cache_path(dir: &Path, digest: &str) -> PathBuf {
    dir.join(format!("{}.boot", digest.replace(':', "-")))
}

/// Return the cached bootstrap path if it already exists on disk. Content-
/// addressed + written atomically, so mere existence implies a complete,
/// digest-verified file.
fn cached_bootstrap(dir: &Path, digest: &str) -> Option<PathBuf> {
    let path = bootstrap_cache_path(dir, digest);
    path.is_file().then_some(path)
}

/// Write a digest-verified bootstrap to its content-addressed cache path,
/// idempotently. If a same-size file is already present it is reused; otherwise
/// the bytes are written to a **uniquely named** temp file and atomically
/// renamed so a partial write can never masquerade as a valid bootstrap.
///
/// The temp file must be unique per writer: two concurrent `Prepare`s of the
/// same image both reach here, and a shared `<digest>.boot.tmp` name lets
/// writer A rename writer B's half-written file into the content-addressed
/// path — which `cached_bootstrap` then trusts forever ("existence implies a
/// complete, digest-verified file").
fn write_bootstrap(dir: &Path, digest: &str, bytes: &[u8]) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create referrer bootstrap dir {}", dir.display()))?;
    let path = bootstrap_cache_path(dir, digest);
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.is_file()
        && meta.len() == bytes.len() as u64
    {
        return Ok(path);
    }
    let mut tmp = tempfile::Builder::new()
        .prefix(".boot.tmp.")
        .tempfile_in(dir)
        .with_context(|| format!("create referrer bootstrap temp file in {}", dir.display()))?;
    std::io::Write::write_all(&mut tmp, bytes)
        .with_context(|| format!("write referrer bootstrap {}", tmp.path().display()))?;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("sync referrer bootstrap {}", tmp.path().display()))?;
    tmp.persist(&path)
        .with_context(|| format!("rename referrer bootstrap into place {}", path.display()))?;
    Ok(path)
}

/// Fetch and materialize the bootstrap for a published (referrer-distributed)
/// nydus image, returning the on-disk path to the digest-verified bootstrap.
///
/// `bootstrap_digest` (from [`ReferrerInfo`]) is EITHER an artifact-manifest
/// digest (referrers-index path) or a bootstrap-blob digest (manifest-layers
/// path). We probe the manifest endpoint first: if the digest resolves to an
/// OCI manifest carrying a nydus-bootstrap layer, that layer's blob is the
/// bootstrap; otherwise `bootstrap_digest` is itself the bootstrap blob and we
/// fetch it directly. The final blob is sha256-verified before it touches disk.
pub async fn materialize_bootstrap(
    image_ref: &str,
    bootstrap_digest: &str,
    config: &SnapshotterConfig,
    cache_dir: &Path,
) -> Result<PathBuf> {
    let parsed = parse_image_ref(image_ref).context("invalid image reference")?;
    let client = build_registry_client(&parsed, config)?;
    let repo = parsed.repo.as_str();
    let dir = cache_dir.join("referrer-bootstraps");

    // Fast path: the referrer digest may itself be the (already-materialized)
    // bootstrap blob (manifest-layers path). Avoids any network round-trip.
    if let Some(path) = cached_bootstrap(&dir, bootstrap_digest) {
        debug!(image = %image_ref, bootstrap = bootstrap_digest, "reusing cached referrer bootstrap");
        return Ok(path);
    }

    // Probe the manifest endpoint. A bootstrap-blob digest 404s here, so an
    // error just routes us to the direct-blob branch below. (`get_manifest`
    // by digest also verifies the returned bytes against it.)
    let layer_digest = match client.get_manifest(repo, bootstrap_digest).await {
        Ok(fetched) => select_nydus_bootstrap_layer(&fetched.bytes),
        Err(e) => {
            debug!(image = %image_ref, bootstrap = bootstrap_digest, error = %e, "manifest probe failed; treating referrer digest as a bootstrap blob");
            None
        }
    };

    let (final_digest, bytes) = match layer_digest {
        Some(layer_digest) => {
            // Artifact-manifest path: the bootstrap is the nydus layer blob.
            if let Some(path) = cached_bootstrap(&dir, &layer_digest) {
                debug!(image = %image_ref, bootstrap = %layer_digest, "reusing cached referrer bootstrap layer");
                return Ok(path);
            }
            let bytes = client
                .get_blob(repo, &layer_digest)
                .await
                .with_context(|| format!("fetch nydus bootstrap layer {layer_digest}"))?;
            (layer_digest, bytes)
        }
        None => {
            // Direct-blob path: bootstrap_digest is the bootstrap blob.
            let bytes = client
                .get_blob(repo, bootstrap_digest)
                .await
                .with_context(|| format!("fetch referrer bootstrap blob {bootstrap_digest}"))?;
            (bootstrap_digest.to_string(), bytes)
        }
    };

    // Never write or mount an unverified bootstrap.
    verify_bootstrap_digest(&bytes, &final_digest)?;
    // A referrer artifact ships the bootstrap raw; a nydus image manifest (the dual-index
    // path) ships it as a gzip tar holding image/image.boot. Unwrap AFTER digest
    // verification -- the declared digest is of the layer blob, not its contents.
    let bytes = maybe_unwrap_bootstrap_layer(bytes)?;
    let path = write_bootstrap(&dir, &final_digest, &bytes)?;
    info!(image = %image_ref, bootstrap = %final_digest, path = %path.display(), "materialized referrer bootstrap");
    Ok(path)
}

/// Synchronous (blocking) entry point for [`materialize_bootstrap`]: drives all
/// cyper HTTP on the thread-local compio runtime and blocks the calling thread
/// until it completes (cyper's `Client` is `!Send`, so it must run to
/// completion on one thread that owns the runtime).
///
/// A plain synchronous caller (integration tests, tools) can call this
/// directly. A caller already on an async runtime — e.g. the gRPC `prepare`
/// task on compio — MUST offload it via `blocking::unblock` so it neither
/// blocks the reactor nor nests a `block_on` inside the running runtime. This
/// is the same threading model as [`detect_referrer_blocking`], just with the
/// `blocking::unblock` hop moved to the call site so the function itself stays
/// usable from ordinary synchronous code.
pub fn materialize_bootstrap_blocking(
    image_ref: &str,
    bootstrap_digest: &str,
    config: &SnapshotterConfig,
    cache_dir: &Path,
) -> Result<PathBuf> {
    REFERRER_HTTP_RUNTIME.with(|rt| {
        rt.block_on(materialize_bootstrap(
            image_ref,
            bootstrap_digest,
            config,
            cache_dir,
        ))
    })
}

/// The referrers-API fallback tag for a subject digest: `sha256:<hex>`
/// becomes `sha256-<hex>`. Must match nydusify's `fallback_referrers_tag`
/// (`nydusify/src/engine/artifact.rs`), which publishes under it.
fn fallback_referrers_tag(digest: &str) -> String {
    digest.replace(':', "-")
}

fn global_cache() -> &'static Mutex<ReferrerCache> {
    REFERRER_CACHE.get_or_init(|| Mutex::new(ReferrerCache::new(DEFAULT_CACHE_CAPACITY)))
}

/// Ceiling on the decompressed bootstrap layer: far above any real bootstrap, low enough
/// that a hostile few-KB gzip cannot OOM the snapshotter.
const MAX_BOOTSTRAP_LAYER_BYTES: u64 = 1024 * 1024 * 1024;

/// If `bytes` is a gzip'd (or plain) tar carrying `image/image.boot`, return that entry;
/// otherwise return `bytes` unchanged (a raw referrer bootstrap).
fn maybe_unwrap_bootstrap_layer(bytes: Vec<u8>) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let tar_bytes: std::borrow::Cow<'_, [u8]> = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut buf = Vec::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .take(MAX_BOOTSTRAP_LAYER_BYTES.saturating_add(1))
            .read_to_end(&mut buf)
            .context("gunzip nydus bootstrap layer")?;
        if buf.len() as u64 > MAX_BOOTSTRAP_LAYER_BYTES {
            bail!(
                "bootstrap layer decompresses past {MAX_BOOTSTRAP_LAYER_BYTES} bytes; refusing to buffer it"
            );
        }
        std::borrow::Cow::Owned(buf)
    } else if bytes.len() > 262 && &bytes[257..262] == b"ustar" {
        std::borrow::Cow::Borrowed(bytes.as_slice())
    } else {
        // Raw bootstrap (RAFS superblock), the referrer-artifact shape.
        return Ok(bytes);
    };

    let mut archive = tar::Archive::new(tar_bytes.as_ref());
    for entry in archive.entries().context("read bootstrap layer tar")? {
        let mut entry = entry.context("read bootstrap layer tar entry")?;
        if entry
            .path()
            .map(|p| p.as_os_str() == "image/image.boot")
            .unwrap_or(false)
        {
            let mut out = Vec::new();
            entry
                .read_to_end(&mut out)
                .context("extract image/image.boot")?;
            return Ok(out);
        }
    }
    bail!("bootstrap layer tar carries no image/image.boot entry")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_evicts_least_recently_used() {
        let mut cache = ReferrerCache::new(2);
        cache.insert("a".to_string(), standard_oci());
        cache.insert("b".to_string(), standard_oci());
        assert!(cache.get("a").is_some());
        cache.insert("c".to_string(), standard_oci());
        assert!(cache.get("a").is_some());
        assert!(cache.get("b").is_none());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn detects_nydus_descriptor_from_index_json() {
        let payload = br#"{
            "manifests":[{
                "mediaType":"application/vnd.oci.image.layer.nydus.bootstrap.v1",
                "digest":"sha256:boot",
                "annotations":{
                    "containerd.io/snapshot/nydus-bootstrap":"true",
                    "containerd.io/snapshot/nydus-fs-driver":"fanotify"
                }
            }]
        }"#;
        let info = detect_from_oci_json(payload).unwrap();
        assert_eq!(info.image_type, ImageType::NydusRafs);
        assert_eq!(info.bootstrap_digest.as_deref(), Some("sha256:boot"));
        assert_eq!(info.fs_driver_hint.as_deref(), Some("fanotify"));
    }

    /// REGRESSION (P4c/P4d review): on the fallback-tag path the artifact
    /// MANIFEST is what gets classified, and its layers list data blobs
    /// (media type also containing "nydus") BEFORE the bootstrap. The old
    /// loose first-match returned the data blob's digest as the "bootstrap",
    /// and the serving path then mounted data bytes as RAFS metadata.
    #[test]
    fn detects_bootstrap_not_data_blob_from_artifact_manifest_layers() {
        let payload = br#"{
            "schemaVersion":2,
            "mediaType":"application/vnd.oci.image.manifest.v1+json",
            "artifactType":"application/vnd.oci.image.layer.nydus.blob.v1",
            "layers":[
                {"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:DATABLOB"},
                {"mediaType":"application/vnd.oci.image.bootstrap.nydus.v1","digest":"sha256:BOOTSTRAP",
                 "annotations":{"containerd.io/snapshot/nydus-bootstrap":"true"}}
            ]
        }"#;
        let info = detect_from_oci_json(payload).unwrap();
        assert_eq!(info.image_type, ImageType::NydusRafs);
        assert_eq!(
            info.bootstrap_digest.as_deref(),
            Some("sha256:BOOTSTRAP"),
            "layers branch must select the bootstrap layer, never the leading data blob"
        );
    }

    /// Media-type fallback (no annotation) must also pick the bootstrap over
    /// the data blob, and a blobs-only manifest (no identifiable bootstrap)
    /// must classify StandardOci — safe overlay, never a garbage mount.
    #[test]
    fn artifact_manifest_without_bootstrap_layer_is_standard_oci() {
        let no_annotation = br#"{
            "layers":[
                {"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:DATABLOB"},
                {"mediaType":"application/vnd.oci.image.bootstrap.nydus.v1","digest":"sha256:BOOTSTRAP"}
            ]
        }"#;
        let info = detect_from_oci_json(no_annotation).unwrap();
        assert_eq!(info.bootstrap_digest.as_deref(), Some("sha256:BOOTSTRAP"));

        let blobs_only = br#"{
            "layers":[
                {"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:DATABLOB1"},
                {"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:DATABLOB2"}
            ]
        }"#;
        let info = detect_from_oci_json(blobs_only).unwrap();
        assert_eq!(
            info.image_type,
            ImageType::StandardOci,
            "nydus data blobs with no identifiable bootstrap must fall back to overlay"
        );
    }

    #[test]
    fn detects_blockdev_hint_from_descriptor() {
        let payload = br#"{
            "manifests":[{
                "artifactType":"application/vnd.oci.image.layer.erofs.v1",
                "digest":"sha256:erofs"
            }]
        }"#;
        let info = detect_from_oci_json(payload).unwrap();
        assert_eq!(info.image_type, ImageType::OciBlockDevice);
        assert_eq!(info.fs_driver_hint.as_deref(), Some("blockdev"));
    }

    /// `[backends.registry]` plumbing lands on the shared client's options:
    /// plain_http, skip_verify → insecure_tls, ca_cert_files, request_timeout
    /// — and docker `config.json` is never consulted (the snapshotter's auth
    /// policy is runtime-injected credentials only, carried via `raw_auth`).
    #[test]
    fn client_options_map_backend_registry_config() {
        // Default (no [backends.registry]) => secure, docker-config-free.
        let opts = client_options_from_config(&SnapshotterConfig::default(), None);
        assert!(!opts.plain_http, "default scheme must be https");
        assert!(!opts.insecure_tls);
        assert!(opts.ca_cert_files.is_empty());
        assert!(
            !opts.use_docker_config,
            "must never read docker config.json"
        );
        assert_eq!(opts.timeout, Some(Duration::from_secs(30)));
        assert!(opts.raw_auth.is_none());

        let mut config = SnapshotterConfig::default();
        config.backends.registry = Some(crate::config::RegistryBackendConfig {
            mirrors: Vec::new(),
            skip_verify: true,
            ca_cert_files: vec!["/etc/ssl/private-ca.pem".to_string()],
            plain_http: true,
            request_timeout: "5s".to_string(),
        });
        let opts = client_options_from_config(&config, Some("dXNlcjpwYXNz".to_string()));
        assert!(opts.plain_http);
        assert!(opts.insecure_tls, "skip_verify must map to insecure_tls");
        assert_eq!(
            opts.ca_cert_files,
            vec![PathBuf::from("/etc/ssl/private-ca.pem")]
        );
        assert_eq!(opts.timeout, Some(Duration::from_secs(5)));
        assert_eq!(opts.raw_auth.as_deref(), Some("dXNlcjpwYXNz"));
        assert!(!opts.use_docker_config);
    }

    fn dual_index_bytes(
        artifact_type: Option<&str>,
        os_features: Option<&str>,
        arch: &str,
    ) -> Vec<u8> {
        let features = os_features
            .map(|f| format!(",\"os.features\":[\"{f}\"]"))
            .unwrap_or_default();
        let at = artifact_type
            .map(|a| format!(",\"artifactType\":\"{a}\""))
            .unwrap_or_default();
        format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[\
             {{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:oci\",\"size\":1,\"platform\":{{\"os\":\"linux\",\"architecture\":\"{arch}\"}}}},\
             {{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:nydus\",\"size\":1{at},\"platform\":{{\"os\":\"linux\",\"architecture\":\"{arch}\"{features}}}}}]}}"
        )
        .into_bytes()
    }

    /// A dual index whose nydus entry carries the given raw `"platform"` JSON
    /// (or none at all), so the platform-matching rules can be pinned directly.
    fn dual_index_with_nydus_platform(platform_json: Option<&str>) -> Vec<u8> {
        let platform = platform_json
            .map(|p| format!(",\"platform\":{p}"))
            .unwrap_or_default();
        format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[\
             {{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:oci\",\"size\":1,\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}},\
             {{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:nydus\",\"size\":1,\"artifactType\":\"application/vnd.nydus.image.manifest.v1+json\"{platform}}}]}}"
        )
        .into_bytes()
    }

    #[test]
    fn dual_index_sibling_is_detected_by_either_marker_for_this_arch() {
        let arch = registry_client::host_go_arch().to_string();
        for (at, osf) in [
            (Some("application/vnd.nydus.image.manifest.v1+json"), None),
            (None, Some("nydus.remoteimage.v1")),
        ] {
            let info = super::classify_dual_index(&dual_index_bytes(at, osf, &arch))
                .expect("marked sibling must be detected");
            assert_eq!(info.image_type, ImageType::NydusRafs);
            assert_eq!(info.bootstrap_digest.as_deref(), Some("sha256:nydus"));
        }
    }

    #[test]
    fn dual_index_sibling_for_another_arch_or_unmarked_is_ignored() {
        // Another architecture's nydus entry must not be served here.
        let other = if std::env::consts::ARCH == "aarch64" {
            "amd64"
        } else {
            "arm64"
        };
        assert!(
            super::classify_dual_index(&dual_index_bytes(
                Some("application/vnd.nydus.image.manifest.v1+json"),
                None,
                other
            ))
            .is_none()
        );
        // An index with no marked entry, and a plain manifest body, both classify as nothing.
        let arch = registry_client::host_go_arch().to_string();
        assert!(super::classify_dual_index(&dual_index_bytes(None, None, &arch)).is_none());
        assert!(super::classify_dual_index(b"{\"schemaVersion\":2,\"config\":{}}").is_none());
    }

    /// A marked entry with no platform at all must NOT be served: it can only
    /// come from a foreign tool, it could have been built for any architecture,
    /// and nothing downstream would notice the mismatch before the container
    /// fails to exec.
    #[test]
    fn dual_index_sibling_without_a_platform_is_not_served() {
        assert!(super::classify_dual_index(&dual_index_with_nydus_platform(None)).is_none());
    }

    /// `arm64` and `arm64/v8` are the same platform spelled two ways, so an
    /// entry carrying either must be served on an arm64 node. 32-bit `arm`
    /// variants are genuinely different images and must never conflate.
    #[test]
    fn dual_index_platform_matching_normalizes_variants() {
        let host = registry_client::host_go_arch();

        let with_variant =
            format!("{{\"os\":\"linux\",\"architecture\":\"{host}\",\"variant\":\"v8\"}}");
        let bare = format!("{{\"os\":\"linux\",\"architecture\":\"{host}\"}}");
        // Only meaningful on arm64, where v8 is the baseline spelling; on other
        // arches the variant is simply a mismatch, which the next case covers.
        if host == "arm64" {
            for platform in [with_variant.as_str(), bare.as_str()] {
                assert!(
                    super::classify_dual_index(&dual_index_with_nydus_platform(Some(platform)))
                        .is_some(),
                    "arm64 must match whether or not v8 is spelled out: {platform}"
                );
            }
        }

        // arm/v6 must not be served for an arm/v7 host and vice versa.
        for (entry, other) in [("v6", "v7"), ("v7", "v6")] {
            let platform =
                format!("{{\"os\":\"linux\",\"architecture\":\"arm\",\"variant\":\"{entry}\"}}");
            let info = super::classify_dual_index(&dual_index_with_nydus_platform(Some(&platform)));
            assert!(
                info.is_none(),
                "arm/{entry} must not be served on a {host} node (nor conflated with arm/{other})"
            );
        }
    }

    #[test]
    fn bootstrap_layer_unwrap_handles_all_three_shapes() {
        use std::io::Write as _;
        // gzip tar with image/image.boot
        let mut tarb = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tarb);
            let mut h = tar::Header::new_gnu();
            h.set_size(9);
            h.set_cksum();
            b.append_data(&mut h, "image/image.boot", &b"BOOTSTRAP"[..])
                .unwrap();
            b.into_inner().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tarb).unwrap();
        let gzipped = gz.finish().unwrap();
        assert_eq!(
            super::maybe_unwrap_bootstrap_layer(gzipped).unwrap(),
            b"BOOTSTRAP"
        );
        // plain tar
        assert_eq!(
            super::maybe_unwrap_bootstrap_layer(tarb).unwrap(),
            b"BOOTSTRAP"
        );
        // raw bootstrap passes through untouched
        let raw = vec![0u8; 64];
        assert_eq!(
            super::maybe_unwrap_bootstrap_layer(raw.clone()).unwrap(),
            raw
        );
    }

    #[test]
    fn fallback_tag_matches_referrers_tag_schema() {
        assert_eq!(fallback_referrers_tag("sha256:deadbeef"), "sha256-deadbeef");
    }

    /// A typed referrers-API index (what `RegistryClient::get_referrers`
    /// returns) classifies through the same single code path as the raw
    /// payloads: a nydus artifact descriptor — nydusify publishes
    /// `artifactType = application/vnd.oci.image.layer.nydus.blob.v1` — wins
    /// over unrelated referrers, and erofs artifacts classify as blockdev.
    #[test]
    fn classify_referrers_index_selects_nydus_artifact() {
        use registry_client::{Descriptor, Index};

        let sbom = Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: "sha256:sbom".to_string(),
            artifact_type: Some("application/spdx+json".to_string()),
            ..Descriptor::default()
        };
        let nydus = Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: "sha256:nydusartifact".to_string(),
            artifact_type: Some(registry_client::types::MEDIA_TYPE_NYDUS_BLOB.to_string()),
            ..Descriptor::default()
        };
        let index = Index {
            schema_version: 2,
            manifests: vec![sbom.clone(), nydus],
            ..Index::default()
        };
        let info = classify_referrers_index(&index).unwrap();
        assert_eq!(info.image_type, ImageType::NydusRafs);
        // The referrers-index entry digest is the artifact MANIFEST digest;
        // materialize_bootstrap later resolves the bootstrap layer out of it.
        assert_eq!(
            info.bootstrap_digest.as_deref(),
            Some("sha256:nydusartifact")
        );

        let erofs = Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: "sha256:erofs".to_string(),
            artifact_type: Some("application/vnd.oci.image.layer.erofs.v1".to_string()),
            ..Descriptor::default()
        };
        let index = Index {
            schema_version: 2,
            manifests: vec![erofs],
            ..Index::default()
        };
        let info = classify_referrers_index(&index).unwrap();
        assert_eq!(info.image_type, ImageType::OciBlockDevice);

        // Unrelated referrers only => StandardOci (no nydus serving).
        let index = Index {
            schema_version: 2,
            manifests: vec![sbom],
            ..Index::default()
        };
        let info = classify_referrers_index(&index).unwrap();
        assert_eq!(info.image_type, ImageType::StandardOci);
    }

    /// A cached NydusRafs result short-circuits `detect_referrer_with_config`
    /// with zero registry interaction. This pins the "one lookup ever, not
    /// per-Prepare" contract and lets the hot path assume a warm cache is free.
    /// The image ref is deliberately unresolvable — if the cache were bypassed,
    /// the call would attempt (and fail/hang on) a live registry round-trip.
    #[compio::test]
    async fn cached_nydus_hit_short_circuits_registry() {
        let image_ref = "registry.invalid.test/cached/nydus:1";
        let seeded = ReferrerInfo {
            image_type: ImageType::NydusRafs,
            bootstrap_digest: Some("sha256:cachedboot".to_string()),
            fs_driver_hint: Some("fanotify".to_string()),
        };
        global_cache()
            .lock()
            .unwrap()
            .insert(image_ref.to_string(), seeded.clone());

        let info = detect_referrer_with_config(image_ref, &SnapshotterConfig::default())
            .await
            .expect("cached hit must resolve without a network call");
        assert_eq!(info.image_type, ImageType::NydusRafs);
        assert_eq!(info.bootstrap_digest.as_deref(), Some("sha256:cachedboot"));
    }

    fn sha256_digest(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    /// (i) Direct-blob case: a raw bootstrap blob is not JSON, so layer
    /// selection returns None and `materialize_bootstrap` takes the direct path.
    #[test]
    fn select_layer_returns_none_for_raw_bootstrap_blob() {
        // Arbitrary binary that is not valid OCI-manifest JSON.
        let blob = [0u8, 1, 2, 3, 0xff, 0xfe, b'{', b'x'];
        assert_eq!(select_nydus_bootstrap_layer(&blob), None);
        // An empty-layers manifest is also treated as a direct blob.
        let empty = br#"{"layers":[]}"#;
        assert_eq!(select_nydus_bootstrap_layer(empty), None);
    }

    /// (ii) Artifact-manifest case: pick the nydus-bootstrap layer's digest out
    /// of a manifest that also carries a plain (non-nydus) layer.
    #[test]
    fn select_layer_picks_the_nydus_bootstrap_layer() {
        let manifest = br#"{
            "layers":[
                {"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:plainlayer"},
                {
                    "mediaType":"application/vnd.oci.image.layer.nydus.bootstrap.v1",
                    "digest":"sha256:bootlayer",
                    "annotations":{"containerd.io/snapshot/nydus-bootstrap":"true"}
                }
            ]
        }"#;
        assert_eq!(
            select_nydus_bootstrap_layer(manifest).as_deref(),
            Some("sha256:bootlayer")
        );
    }

    /// Regression: a real published nydus artifact lists its data-blob layers
    /// (mediaType `...layer.nydus.blob.v1`, which contains "nydus") BEFORE the
    /// bootstrap layer. A loose "contains nydus" match would return the first
    /// data blob; we must select the annotated bootstrap layer instead — else
    /// `ensure_instance` is handed a data blob and the feature degrades to
    /// overlay on exactly the multi-blob artifacts B4b targets.
    #[test]
    fn select_layer_skips_data_blobs_before_the_bootstrap() {
        let manifest = br#"{
            "layers":[
                {"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:datablob0"},
                {"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:datablob1"},
                {
                    "mediaType":"application/vnd.oci.image.layer.nydus.bootstrap.v1",
                    "digest":"sha256:realboot",
                    "annotations":{"containerd.io/snapshot/nydus-bootstrap":"true"}
                }
            ]
        }"#;
        assert_eq!(
            select_nydus_bootstrap_layer(manifest).as_deref(),
            Some("sha256:realboot"),
            "must select the bootstrap layer, not a leading data blob"
        );
    }

    /// When the manifest lists only data-blob layers and no bootstrap (neither
    /// annotation nor a `bootstrap` media type), selection returns None so the
    /// caller falls back to the direct-blob path rather than mounting a data
    /// blob as if it were a bootstrap.
    #[test]
    fn select_layer_returns_none_without_a_bootstrap_layer() {
        let manifest = br#"{
            "layers":[
                {"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:datablob0"},
                {"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:datablob1"}
            ]
        }"#;
        assert_eq!(select_nydus_bootstrap_layer(manifest), None);
    }

    /// The media-type fallback selects a `...bootstrap.nydus...` layer even when
    /// the reliable annotation is absent.
    #[test]
    fn select_layer_falls_back_to_bootstrap_media_type() {
        let manifest = br#"{
            "layers":[
                {"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:datablob0"},
                {"mediaType":"application/vnd.oci.image.layer.bootstrap.nydus.v1","digest":"sha256:mediaboot"}
            ]
        }"#;
        assert_eq!(
            select_nydus_bootstrap_layer(manifest).as_deref(),
            Some("sha256:mediaboot")
        );
    }

    /// (iii) A tampered bootstrap fails digest verification and is rejected.
    #[test]
    fn verify_bootstrap_digest_rejects_mismatch() {
        let bytes = b"the real bootstrap bytes";
        let good = sha256_digest(bytes);
        verify_bootstrap_digest(bytes, &good).expect("matching digest must verify");
        verify_bootstrap_digest(b"tampered bytes", &good)
            .expect_err("mismatched digest must be rejected");
        // Non-sha256 algorithms are unsupported.
        verify_bootstrap_digest(bytes, "sha512:deadbeef")
            .expect_err("non-sha256 digest must be rejected");
    }

    /// (iv) Writing is idempotent: a second write reuses the existing digest-
    /// named file and `cached_bootstrap` finds it without a fetch.
    #[test]
    fn write_bootstrap_is_idempotent_and_cacheable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("referrer-bootstraps");
        let bytes = b"bootstrap contents";
        let digest = sha256_digest(bytes);

        assert!(cached_bootstrap(&root, &digest).is_none());
        let first = write_bootstrap(&root, &digest, bytes).unwrap();
        assert!(first.is_file());
        // Reuse: cached lookup finds the same path, no temp files linger.
        assert_eq!(
            cached_bootstrap(&root, &digest).as_deref(),
            Some(first.as_path())
        );
        let second = write_bootstrap(&root, &digest, bytes).unwrap();
        assert_eq!(first, second);
        assert_eq!(std::fs::read(&second).unwrap(), bytes);
    }

    /// StandardOci results are cached too, so a plain image also costs at most
    /// one lookup — the cached miss returns instantly with no registry call.
    #[compio::test]
    async fn cached_standard_oci_short_circuits_registry() {
        let image_ref = "registry.invalid.test/cached/plain:1";
        global_cache()
            .lock()
            .unwrap()
            .insert(image_ref.to_string(), standard_oci());

        let info = detect_referrer_with_config(image_ref, &SnapshotterConfig::default())
            .await
            .expect("cached StandardOci must resolve without a network call");
        assert_eq!(info.image_type, ImageType::StandardOci);
    }
}
