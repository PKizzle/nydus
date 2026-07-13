// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Referrer-based image source detection.
//!
//! Inspects OCI image manifests or OCI referrer/index descriptors to determine
//! whether an image is a Nydus-optimized image and how to serve it.

use crate::cache::parse_duration;
use crate::config::SnapshotterConfig;
use crate::daemon::auth::resolve_auth;
use crate::daemon::image_ref::{ImageRef, parse_image_ref};
use anyhow::{Context, Result, anyhow, bail};
use cyper::{Client, Response};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, HeaderValue, WWW_AUTHENTICATE};
use http::{Method, StatusCode};
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
/// Accept header for a raw blob (bootstrap) GET.
const BLOB_ACCEPT: &str = "application/octet-stream";
/// Upper bound on a registry body we will buffer into memory (manifest or
/// bootstrap blob). A published nydus bootstrap is the merged RAFS metadata for
/// the whole image, which stays comfortably under this even for large images;
/// the cap only exists so a hostile or misbehaving registry cannot OOM the
/// snapshotter. 512 MiB is deliberately generous.
const MAX_REGISTRY_BODY_BYTES: u64 = 512 * 1024 * 1024;
const OCI_INDEX_ACCEPT: &str = concat!(
    "application/vnd.oci.image.index.v1+json, ",
    "application/vnd.docker.distribution.manifest.list.v2+json, ",
    "application/vnd.oci.image.manifest.v1+json, ",
    "application/vnd.docker.distribution.manifest.v2+json"
);

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

/// Small OCI Distribution client for referrer discovery.
#[derive(Clone)]
pub struct RegistryReferrerClient {
    client: Client,
    scheme: &'static str,
    timeout: Duration,
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
    match RegistryReferrerClient::from_config(config)?
        .detect(image_ref, config)
        .await
    {
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

impl RegistryReferrerClient {
    pub fn from_config(config: &SnapshotterConfig) -> Result<Self> {
        let registry = config.backends.registry.as_ref();
        let timeout = registry
            .and_then(|cfg| parse_duration(&cfg.request_timeout).ok())
            .unwrap_or_else(|| Duration::from_secs(30));
        let skip_verify = registry.map(|cfg| cfg.skip_verify).unwrap_or(false);
        // Transport scheme. HTTPS by default (secure). `[backends.registry]
        // plain_http = true` opts the registry into cleartext HTTP, mirroring
        // the same opt-in the storage backend already honors.
        //
        // SECURITY: plain HTTP disables transport encryption AND server
        // authentication, so an on-path attacker can read and *tamper with*
        // referrer manifests and bootstrap blobs. Because the artifact manifest
        // — which declares the bootstrap's expected digest — is fetched over the
        // same cleartext channel, B4b's bootstrap digest verification does NOT
        // protect against a MITM here: they control both the declared digest and
        // the served bytes, so a forged bootstrap verifies fine. This is the same
        // exposure as any plain-HTTP image pull; only enable it for registries on
        // a trusted network (loopback, air-gapped, private LAN).
        let plain_http = registry.map(|cfg| cfg.plain_http).unwrap_or(false);
        let scheme = if plain_http { "http" } else { "https" };
        // cyper has no client-level timeout; it is applied per request via
        // `compio::time::timeout` in `send_once` / `fetch_bearer_token`.
        let client = Client::builder()
            .use_rustls_default()
            .danger_accept_invalid_certs(skip_verify)
            .build()
            .context("failed to build registry referrer HTTP client")?;
        Ok(Self {
            client,
            scheme,
            timeout,
        })
    }

    async fn detect(
        &self,
        image_ref: &str,
        config: &SnapshotterConfig,
    ) -> Result<Option<ReferrerInfo>> {
        let parsed = parse_image_ref(image_ref).context("invalid image reference")?;
        let auth = resolve_auth(config, &parsed);
        let Some(digest) = self.resolve_digest(&parsed, auth.as_deref()).await? else {
            return Ok(None);
        };

        if let Some(payload) = self
            .fetch_referrers(&parsed, &digest, auth.as_deref())
            .await?
        {
            let info = detect_from_oci_json(&payload)?;
            if info.image_type != ImageType::StandardOci {
                return Ok(Some(info));
            }
        }

        if let Some(payload) = self
            .fetch_referrers_fallback_tag(&parsed, &digest, auth.as_deref())
            .await?
        {
            let info = detect_from_oci_json(&payload)?;
            if info.image_type != ImageType::StandardOci {
                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    async fn resolve_digest(&self, image: &ImageRef, auth: Option<&str>) -> Result<Option<String>> {
        if let Some(digest) = image.digest.as_ref() {
            return Ok(Some(digest.clone()));
        }
        let Some(reference) = image.tag.as_deref() else {
            return Ok(None);
        };

        let url = self.manifest_url(image, reference);
        let mut used_get = false;
        let mut response = self
            .registry_request(Method::HEAD, &url, OCI_INDEX_ACCEPT, image, auth)
            .await?;
        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            used_get = true;
            response = self
                .registry_request(Method::GET, &url, OCI_INDEX_ACCEPT, image, auth)
                .await?;
        }
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            bail!(
                "registry manifest digest resolution failed with HTTP {}",
                response.status()
            );
        }
        if let Some(digest) = response
            .headers()
            .get("docker-content-digest")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
        {
            return Ok(Some(digest));
        }
        // Registries are not required to send Docker-Content-Digest (the OCI
        // distribution spec makes it optional). Fall back to fetching the
        // manifest body and hashing it — a HEAD gave us no body, so re-issue as
        // a GET. Without this, such a registry classified every image as
        // StandardOci (and, before the negative-cache fix, cached that
        // permanently).
        if !used_get {
            response = self
                .registry_request(Method::GET, &url, OCI_INDEX_ACCEPT, image, auth)
                .await?;
            if response.status() == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                bail!(
                    "registry manifest GET (digest fallback) failed with HTTP {}",
                    response.status()
                );
            }
        }
        let body = read_bounded(response).await?;
        Ok(Some(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(&body))
        )))
    }

    async fn fetch_referrers(
        &self,
        image: &ImageRef,
        digest: &str,
        auth: Option<&str>,
    ) -> Result<Option<Vec<u8>>> {
        let url = self.referrers_url(image, digest);
        let response = self
            .registry_request(Method::GET, &url, OCI_INDEX_ACCEPT, image, auth)
            .await?;
        match response.status() {
            StatusCode::OK => Ok(Some(read_bounded(response).await?)),
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::BAD_REQUEST => {
                Ok(None)
            }
            status if status.is_success() => Ok(Some(read_bounded(response).await?)),
            status => {
                warn!(%status, "registry referrers query returned non-success status");
                Ok(None)
            }
        }
    }

    async fn fetch_referrers_fallback_tag(
        &self,
        image: &ImageRef,
        digest: &str,
        auth: Option<&str>,
    ) -> Result<Option<Vec<u8>>> {
        let reference = fallback_referrers_tag(digest);
        let url = self.manifest_url(image, &reference);
        let response = self
            .registry_request(Method::GET, &url, OCI_INDEX_ACCEPT, image, auth)
            .await?;
        match response.status() {
            StatusCode::OK => Ok(Some(read_bounded(response).await?)),
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::BAD_REQUEST => {
                Ok(None)
            }
            status if status.is_success() => Ok(Some(read_bounded(response).await?)),
            _ => Ok(None),
        }
    }

    async fn registry_request(
        &self,
        method: Method,
        url: &str,
        accept: &str,
        image: &ImageRef,
        auth: Option<&str>,
    ) -> Result<Response> {
        let response = self
            .send_once(
                method.clone(),
                url,
                accept,
                auth.map(auth_header_value).transpose()?,
            )
            .await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let Some(challenge) = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_bearer_challenge)
        else {
            return Ok(response);
        };
        let token = self.fetch_bearer_token(&challenge, image, auth).await?;
        let header = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("registry bearer token contained invalid header characters")?;
        self.send_once(method, url, accept, Some(header)).await
    }

    async fn send_once(
        &self,
        method: Method,
        url: &str,
        accept: &str,
        auth: Option<HeaderValue>,
    ) -> Result<Response> {
        let mut request = self
            .client
            .request(method, url)
            .with_context(|| format!("invalid registry request URL {url}"))?
            .header(ACCEPT, accept)
            .context("invalid Accept header")?;
        if let Some(auth) = auth {
            request = request
                .header(AUTHORIZATION, auth)
                .context("invalid Authorization header")?;
        }
        compio::time::timeout(self.timeout, request.send())
            .await
            .map_err(|_| anyhow!("registry request to {url} timed out"))?
            .with_context(|| format!("registry request failed for {url}"))
    }

    async fn fetch_bearer_token(
        &self,
        challenge: &BearerChallenge,
        image: &ImageRef,
        auth: Option<&str>,
    ) -> Result<String> {
        let scope = challenge
            .scope
            .clone()
            .unwrap_or_else(|| format!("repository:{}:pull", image.repo));
        let mut url = challenge.realm.clone();
        let sep = if url.contains('?') { '&' } else { '?' };
        url.push(sep);
        if let Some(service) = challenge.service.as_deref() {
            url.push_str("service=");
            url.push_str(&percent_encode_query(service));
            url.push('&');
        }
        url.push_str("scope=");
        url.push_str(&percent_encode_query(&scope));

        let mut request = self
            .client
            .get(url)
            .context("invalid registry token URL")?
            .header(ACCEPT, "application/json")
            .context("invalid Accept header")?;
        if let Some(auth) = auth.map(auth_header_value).transpose()? {
            request = request
                .header(AUTHORIZATION, auth)
                .context("invalid Authorization header")?;
        }
        let response = compio::time::timeout(self.timeout, request.send())
            .await
            .map_err(|_| anyhow!("registry token request timed out"))?
            .context("registry token request failed")?;
        if !response.status().is_success() {
            bail!(
                "registry token request failed with HTTP {}",
                response.status()
            );
        }
        let token = response
            .json::<RegistryTokenResponse>()
            .await
            .context("failed to decode registry token response")?
            .into_token()
            .context("registry token response did not include a token")?;
        Ok(token)
    }

    fn manifest_url(&self, image: &ImageRef, reference: &str) -> String {
        format!(
            "{}://{}/v2/{}/manifests/{}",
            self.scheme, image.api_host, image.repo, reference
        )
    }

    fn referrers_url(&self, image: &ImageRef, digest: &str) -> String {
        format!(
            "{}://{}/v2/{}/referrers/{}",
            self.scheme, image.api_host, image.repo, digest
        )
    }

    fn blob_url(&self, image: &ImageRef, digest: &str) -> String {
        format!(
            "{}://{}/v2/{}/blobs/{}",
            self.scheme, image.api_host, image.repo, digest
        )
    }

    /// GET an OCI manifest by digest (`/v2/<repo>/manifests/<digest>`). Reuses
    /// the same bearer/WWW-Authenticate dance as every other registry request.
    /// Errors on any non-success status so the caller can fall back to treating
    /// the digest as a bootstrap blob (a bare blob digest 404s here).
    async fn fetch_manifest_by_digest(
        &self,
        image: &ImageRef,
        digest: &str,
        auth: Option<&str>,
    ) -> Result<Vec<u8>> {
        let url = self.manifest_url(image, digest);
        let response = self
            .registry_request(Method::GET, &url, OCI_INDEX_ACCEPT, image, auth)
            .await?;
        if !response.status().is_success() {
            bail!(
                "registry manifest fetch for {digest} failed with HTTP {}",
                response.status()
            );
        }
        read_bounded(response).await
    }

    /// GET a blob by digest (`/v2/<repo>/blobs/<digest>`). Same bearer dance,
    /// blob Accept header, bounded read.
    async fn fetch_blob(
        &self,
        image: &ImageRef,
        digest: &str,
        auth: Option<&str>,
    ) -> Result<Vec<u8>> {
        let url = self.blob_url(image, digest);
        let response = self
            .registry_request(Method::GET, &url, BLOB_ACCEPT, image, auth)
            .await?;
        if !response.status().is_success() {
            bail!(
                "registry blob fetch for {digest} failed with HTTP {}",
                response.status()
            );
        }
        read_bounded(response).await
    }
}

/// Read a registry response body into memory, rejecting anything larger than
/// [`MAX_REGISTRY_BODY_BYTES`] (checked against the advertised Content-Length up
/// front and against the actual body length after buffering, so a lying header
/// cannot slip a huge body past the cap).
async fn read_bounded(response: Response) -> Result<Vec<u8>> {
    if let Some(len) = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        && len > MAX_REGISTRY_BODY_BYTES
    {
        bail!("registry body of {len} bytes exceeds cap of {MAX_REGISTRY_BODY_BYTES} bytes");
    }
    let bytes = response.bytes().await?;
    if bytes.len() as u64 > MAX_REGISTRY_BODY_BYTES {
        bail!(
            "registry body of {} bytes exceeds cap of {MAX_REGISTRY_BODY_BYTES} bytes",
            bytes.len()
        );
    }
    Ok(bytes.to_vec())
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
    let auth = resolve_auth(config, &parsed);
    let client = RegistryReferrerClient::from_config(config)?;
    let dir = cache_dir.join("referrer-bootstraps");

    // Fast path: the referrer digest may itself be the (already-materialized)
    // bootstrap blob (manifest-layers path). Avoids any network round-trip.
    if let Some(path) = cached_bootstrap(&dir, bootstrap_digest) {
        debug!(image = %image_ref, bootstrap = bootstrap_digest, "reusing cached referrer bootstrap");
        return Ok(path);
    }

    // Probe the manifest endpoint. A bootstrap-blob digest 404s here, so an
    // error just routes us to the direct-blob branch below.
    let layer_digest = match client
        .fetch_manifest_by_digest(&parsed, bootstrap_digest, auth.as_deref())
        .await
    {
        Ok(manifest) => select_nydus_bootstrap_layer(&manifest),
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
                .fetch_blob(&parsed, &layer_digest, auth.as_deref())
                .await
                .with_context(|| format!("fetch nydus bootstrap layer {layer_digest}"))?;
            (layer_digest, bytes)
        }
        None => {
            // Direct-blob path: bootstrap_digest is the bootstrap blob.
            let bytes = client
                .fetch_blob(&parsed, bootstrap_digest, auth.as_deref())
                .await
                .with_context(|| format!("fetch referrer bootstrap blob {bootstrap_digest}"))?;
            (bootstrap_digest.to_string(), bytes)
        }
    };

    // Never write or mount an unverified bootstrap.
    verify_bootstrap_digest(&bytes, &final_digest)?;
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

#[derive(Debug, Deserialize)]
struct RegistryTokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

impl RegistryTokenResponse {
    fn into_token(self) -> Option<String> {
        self.token.or(self.access_token)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

fn auth_header_value(auth: &str) -> Result<HeaderValue> {
    let value = if auth.starts_with("Basic ") || auth.starts_with("Bearer ") {
        auth.to_string()
    } else {
        format!("Basic {auth}")
    };
    HeaderValue::from_str(&value).context("registry auth contained invalid header characters")
}

fn parse_bearer_challenge(value: &str) -> Option<BearerChallenge> {
    let value = value.trim();
    let params = value.strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in split_header_params(params) {
        let (key, raw_value) = part.split_once('=')?;
        let decoded = raw_value.trim().trim_matches('"').to_string();
        match key.trim() {
            "realm" => realm = Some(decoded),
            "service" => service = Some(decoded),
            "scope" => scope = Some(decoded),
            _ => {}
        }
    }
    Some(BearerChallenge {
        realm: realm?,
        service,
        scope,
    })
}

fn split_header_params(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    for (idx, ch) in value.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(value[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    out.push(value[start..].trim());
    out.into_iter().filter(|part| !part.is_empty()).collect()
}

fn percent_encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn fallback_referrers_tag(digest: &str) -> String {
    digest.replace(':', "-")
}

fn global_cache() -> &'static Mutex<ReferrerCache> {
    REFERRER_CACHE.get_or_init(|| Mutex::new(ReferrerCache::new(DEFAULT_CACHE_CAPACITY)))
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

    #[compio::test]
    async fn registry_urls_use_oci_distribution_referrers_endpoint() {
        let client = RegistryReferrerClient {
            client: Client::new().unwrap(),
            scheme: "https",
            timeout: Duration::from_secs(30),
        };
        let image = parse_image_ref("registry.local:5000/team/app:1").unwrap();
        assert_eq!(
            client.manifest_url(&image, "1"),
            "https://registry.local:5000/v2/team/app/manifests/1"
        );
        assert_eq!(
            client.referrers_url(&image, "sha256:abc"),
            "https://registry.local:5000/v2/team/app/referrers/sha256:abc"
        );
    }

    #[compio::test]
    async fn from_config_scheme_defaults_https_and_honors_plain_http() {
        let image = parse_image_ref("registry.local:5000/team/app:1").unwrap();

        // Default (no [backends.registry]) => secure HTTPS.
        let config = SnapshotterConfig::default();
        let client = RegistryReferrerClient::from_config(&config).unwrap();
        assert!(
            client.manifest_url(&image, "1").starts_with("https://"),
            "default referrer scheme must be https"
        );

        // plain_http = true => cleartext HTTP for both manifest and blob fetches.
        let mut config = SnapshotterConfig::default();
        config.backends.registry = Some(crate::config::RegistryBackendConfig {
            mirrors: Vec::new(),
            skip_verify: false,
            ca_cert_files: Vec::new(),
            plain_http: true,
            request_timeout: "30s".to_string(),
        });
        let client = RegistryReferrerClient::from_config(&config).unwrap();
        assert_eq!(
            client.manifest_url(&image, "1"),
            "http://registry.local:5000/v2/team/app/manifests/1"
        );
        assert!(
            client.blob_url(&image, "sha256:abc").starts_with("http://"),
            "plain_http must apply to blob fetches too"
        );
    }

    #[test]
    fn bearer_challenge_parser_handles_quoted_params() {
        let parsed = parse_bearer_challenge(
            r#"Bearer realm="https://auth.local/token",service="registry.local",scope="repository:team/app:pull""#,
        )
        .unwrap();
        assert_eq!(parsed.realm, "https://auth.local/token");
        assert_eq!(parsed.service.as_deref(), Some("registry.local"));
        assert_eq!(parsed.scope.as_deref(), Some("repository:team/app:pull"));
    }

    #[test]
    fn auth_header_preserves_explicit_scheme_or_adds_basic() {
        assert_eq!(auth_header_value("abc").unwrap(), "Basic abc");
        assert_eq!(auth_header_value("Bearer token").unwrap(), "Bearer token");
        assert_eq!(auth_header_value("Basic abc").unwrap(), "Basic abc");
    }

    #[test]
    fn fallback_tag_matches_referrers_tag_schema() {
        assert_eq!(fallback_referrers_tag("sha256:deadbeef"), "sha256-deadbeef");
        assert_eq!(
            percent_encode_query("repository:team/app:pull"),
            "repository%3Ateam%2Fapp%3Apull"
        );
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
