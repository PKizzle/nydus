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
use crate::daemon::image_ref::{parse_image_ref, ImageRef};
use anyhow::{bail, Context, Result};
use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Client, Method, Response, StatusCode};
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tracing::{debug, warn};

const DEFAULT_CACHE_CAPACITY: usize = 500;
const NYDUS_BOOTSTRAP_ANNOTATION: &str = "containerd.io/snapshot/nydus-bootstrap";
const NYDUS_FS_DRIVER_HINT: &str = "containerd.io/snapshot/nydus-fs-driver";
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
    let info = match RegistryReferrerClient::from_config(config)?
        .detect(image_ref, config)
        .await
    {
        Ok(Some(info)) => info,
        Ok(None) => standard_oci(),
        Err(e) => {
            debug!(%image_ref, error = %e, "referrer registry query failed; using StandardOci fallback");
            standard_oci()
        }
    };
    if let Ok(mut cache) = global_cache().lock() {
        cache.insert(image_ref.to_string(), info.clone());
    }
    Ok(info)
}

impl RegistryReferrerClient {
    pub fn from_config(config: &SnapshotterConfig) -> Result<Self> {
        let registry = config.backends.registry.as_ref();
        let timeout = registry
            .and_then(|cfg| parse_duration(&cfg.request_timeout).ok())
            .unwrap_or_else(|| Duration::from_secs(30));
        let skip_verify = registry.map(|cfg| cfg.skip_verify).unwrap_or(false);
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(skip_verify)
            .build()
            .context("failed to build registry referrer HTTP client")?;
        Ok(Self {
            client,
            scheme: "https",
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
        let mut response = self
            .registry_request(Method::HEAD, &url, OCI_INDEX_ACCEPT, image, auth)
            .await?;
        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
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
        Ok(response
            .headers()
            .get("docker-content-digest")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string))
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
            StatusCode::OK => Ok(Some(response.bytes().await?.to_vec())),
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::BAD_REQUEST => {
                Ok(None)
            }
            status if status.is_success() => Ok(Some(response.bytes().await?.to_vec())),
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
            StatusCode::OK => Ok(Some(response.bytes().await?.to_vec())),
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::BAD_REQUEST => {
                Ok(None)
            }
            status if status.is_success() => Ok(Some(response.bytes().await?.to_vec())),
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
        let mut request = self.client.request(method, url).header(ACCEPT, accept);
        if let Some(auth) = auth {
            request = request.header(AUTHORIZATION, auth);
        }
        request
            .send()
            .await
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

        let mut request = self.client.get(url).header(ACCEPT, "application/json");
        if let Some(auth) = auth.map(auth_header_value).transpose()? {
            request = request.header(AUTHORIZATION, auth);
        }
        let response = request
            .send()
            .await
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
}

/// Classify an OCI referrer response or index/manifest JSON payload. This is
/// used as the fallback when registries do not expose the referrers API but do
/// expose an index manifest carrying Nydus descriptors.
pub fn detect_from_oci_json(payload: &[u8]) -> Result<ReferrerInfo> {
    if let Ok(index) = serde_json::from_slice::<OciIndex>(payload) {
        if let Some(info) = index.manifests.iter().find_map(classify_descriptor) {
            return Ok(info);
        }
    }
    if let Ok(manifest) = serde_json::from_slice::<OciManifest>(payload) {
        if let Some(info) = manifest.layers.iter().find_map(classify_descriptor) {
            return Ok(info);
        }
    }
    Ok(standard_oci())
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

    #[test]
    fn registry_urls_use_oci_distribution_referrers_endpoint() {
        let client = RegistryReferrerClient {
            client: Client::new(),
            scheme: "https",
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
}
