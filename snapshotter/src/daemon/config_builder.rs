// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Build a `nydus_api::ConfigV2` JSON document for an in-process FUSE daemon.
//!
//! Mirrors the JSON the Go snapshotter would emit before calling nydusd, but
//! constructed programmatically from the unified TOML config + per-image
//! parameters (image reference, cache directory, auth).

use std::path::Path;

use anyhow::Context;
use tracing::warn;
use nydus_api::{
    BLOB_CACHE_TYPE_META_BLOB, BackendConfigV2, BlobCacheEntry, BlobCacheEntryConfigV2,
    CacheConfigV2, ConfigV2, FanotifyConfig, FileCacheConfig, HttpProxyConfig, LocalFsConfig,
    OssConfig, RafsConfigV2, RegistryConfig, S3Config,
};
use serde_json::json;

use crate::config::{
    HttpProxyBackendConfig, OssBackendConfig, RegistryBackendConfig, S3BackendConfig,
    SnapshotterConfig,
};
use crate::daemon::image_ref::ImageRef;

/// Retry count applied to every daemon storage backend, matching the historical
/// registry-backend value so the object-store / http-proxy backends inherit the
/// same resilience.
const BACKEND_RETRY_LIMIT: u8 = 3;
/// Per-request / connect timeout (seconds) for the object-store and http-proxy
/// backends when no per-backend timeout is expressed in the TOML. Mirrors the
/// nydus-api `default_http_timeout`.
const DEFAULT_HTTP_TIMEOUT_SECS: u32 = 5;

/// Build a `ConfigV2` for the daemon pull path: the storage backend selected
/// from the unified `[backends.*]` TOML config, paired with a filecache.
///
/// `cache_work_dir` is the per-image directory that nydusd uses to materialise
/// chunk caches. `auth` is the optional `base64(user:password)` blob from the
/// runtime auth store — only the registry backend consumes it.
///
/// Backend selection is delegated to [`build_backend_config`]; the cache + rafs
/// sections are backend-independent.
pub fn build_daemon_config(
    cfg: &SnapshotterConfig,
    image_ref: &ImageRef,
    cache_work_dir: &Path,
    auth: Option<String>,
    daemon_id: &str,
) -> anyhow::Result<ConfigV2> {
    let backend = build_backend_config(cfg, image_ref, auth)?;

    let cache = CacheConfigV2 {
        cache_type: "filecache".to_string(),
        cache_compressed: false,
        cache_validate: false,
        prefetch: Default::default(),
        file_cache: Some(FileCacheConfig {
            work_dir: cache_work_dir.display().to_string(),
            disable_indexed_map: cfg.snapshotter.cache.disable_indexed,
            enable_encryption: false,
            enable_convergent_encryption: false,
            encryption_key: String::new(),
        }),
        fanotify: None,
    };

    let rafs = RafsConfigV2 {
        mode: "direct".to_string(),
        user_io_batch_size: 1024 * 1024,
        validate: false,
        enable_xattr: true,
        iostats_files: false,
        access_pattern: false,
        latest_read_files: false,
        prefetch: Default::default(),
    };

    Ok(ConfigV2 {
        version: 2,
        id: daemon_id.to_string(),
        backend: Some(backend),
        external_backends: Vec::new(),
        cache: Some(cache),
        rafs: Some(rafs),
        overlay: None,
        internal: Default::default(),
    })
}

/// Select and build the storage `BackendConfigV2` that drives the daemon pull
/// path from the `[backends.*]` config.
///
/// Selection precedence: at most one of `s3` / `oss` / `http-proxy` / `registry`
/// may be configured (enforced loudly at startup by
/// [`crate::config::BackendsConfig::validate`]). When none is set the image's
/// own registry is used — the historical default. `[backends.localfs]` is NOT
/// handled here: the `localfs` backend is reserved for the auto-accel sidecar
/// path (see [`build_auto_accel_config`]).
///
/// `image_ref` / `auth` are consumed only by the registry backend; the object-
/// store and http-proxy backends are described entirely by their TOML section.
///
/// NOTE: the s3 / oss / http-proxy mappings are unit-tested at the
/// TOML-struct → `ConfigV2` level, but have NOT been integration-tested against
/// a live S3 / OSS / http-proxy endpoint.
pub fn build_backend_config(
    cfg: &SnapshotterConfig,
    image_ref: &ImageRef,
    auth: Option<String>,
) -> anyhow::Result<BackendConfigV2> {
    let backends = &cfg.backends;
    // Defense in depth: `SnapshotterConfig::validate` rejects >1 pull backend
    // at startup, but library callers (tests, embedders) may skip it and the
    // `if let` chain below would then silently pick by precedence. Assert the
    // invariant in debug builds so that path is caught in test.
    debug_assert!(
        backends.pull_backends().len() <= 1,
        "build_backend_config called with multiple pull backends ({:?}); \
         SnapshotterConfig::validate() must run first",
        backends.pull_backends()
    );
    if let Some(s3) = backends.s3.as_ref() {
        build_s3_backend(s3)
    } else if let Some(oss) = backends.oss.as_ref() {
        build_oss_backend(oss)
    } else if let Some(http_proxy) = backends.http_proxy.as_ref() {
        Ok(build_http_proxy_backend(http_proxy))
    } else {
        Ok(build_registry_backend(
            backends.registry.as_ref(),
            image_ref,
            auth,
        ))
    }
}

/// Build the registry `BackendConfigV2`. Preserves the historical behaviour:
/// host/repo come from the image reference, `request_timeout` / `plain_http` /
/// `skip_verify` from the optional `[backends.registry]` section (defaults used
/// when absent).
fn build_registry_backend(
    registry_cfg: Option<&RegistryBackendConfig>,
    image_ref: &ImageRef,
    auth: Option<String>,
) -> BackendConfigV2 {
    let timeout_secs = parse_timeout_seconds(
        registry_cfg
            .map(|c| c.request_timeout.as_str())
            .unwrap_or("30s"),
    );
    let scheme = if registry_cfg.map(|c| c.plain_http).unwrap_or(false) {
        "http"
    } else {
        "https"
    };
    let registry = RegistryConfig {
        scheme: scheme.to_string(),
        host: image_ref.api_host.clone(),
        repo: image_ref.repo.clone(),
        auth,
        skip_verify: registry_cfg.map(|c| c.skip_verify).unwrap_or(false),
        ca_cert_files: registry_cfg
            .map(|c| c.ca_cert_files.clone())
            .unwrap_or_default(),
        timeout: timeout_secs,
        connect_timeout: timeout_secs,
        retry_limit: BACKEND_RETRY_LIMIT,
        registry_token: None,
        blob_url_scheme: String::new(),
        blob_redirected_host: String::new(),
        proxy: Default::default(),
    };

    BackendConfigV2 {
        backend_type: "registry".to_string(),
        localdisk: None,
        localfs: None,
        oss: None,
        s3: None,
        registry: Some(registry),
        http_proxy: None,
    }
}

/// Build the `s3` `BackendConfigV2`. Credentials are resolved from the named
/// environment variables (`access_key_env` / `secret_key_env`); a referenced
/// variable that is not set is a hard error. The `endpoint` is normalised to a
/// bare host and the URL scheme selected via [`resolve_endpoint_scheme`].
fn build_s3_backend(s3: &S3BackendConfig) -> anyhow::Result<BackendConfigV2> {
    let access_key_id = resolve_credential_env(&s3.access_key_env)?;
    let access_key_secret = resolve_credential_env(&s3.secret_key_env)?;
    let (scheme, endpoint) = resolve_endpoint_scheme(&s3.endpoint, s3.insecure);
    let s3_cfg = S3Config {
        scheme,
        endpoint,
        region: s3.region.clone(),
        bucket_name: s3.bucket.clone(),
        object_prefix: s3.object_prefix.clone().unwrap_or_default(),
        access_key_id,
        access_key_secret,
        skip_verify: s3.skip_verify,
        ca_cert_files: s3.ca_cert_files.clone(),
        timeout: DEFAULT_HTTP_TIMEOUT_SECS,
        connect_timeout: DEFAULT_HTTP_TIMEOUT_SECS,
        retry_limit: BACKEND_RETRY_LIMIT,
        proxy: Default::default(),
    };
    Ok(BackendConfigV2 {
        backend_type: "s3".to_string(),
        localdisk: None,
        localfs: None,
        oss: None,
        s3: Some(s3_cfg),
        registry: None,
        http_proxy: None,
    })
}

/// Build the `oss` `BackendConfigV2`. Credentials are optional: an empty
/// `access_key_env` / `secret_key_env` yields blank keys (anonymous / public
/// bucket access); a non-empty name that is unset is a hard error. The
/// `endpoint` is normalised to a bare host and the URL scheme selected via
/// [`resolve_endpoint_scheme`].
fn build_oss_backend(oss: &OssBackendConfig) -> anyhow::Result<BackendConfigV2> {
    let access_key_id = resolve_credential_env(&oss.access_key_env)?;
    let access_key_secret = resolve_credential_env(&oss.secret_key_env)?;
    let (scheme, endpoint) = resolve_endpoint_scheme(&oss.endpoint, oss.insecure);
    let oss_cfg = OssConfig {
        scheme,
        endpoint,
        bucket_name: oss.bucket.clone(),
        object_prefix: oss.object_prefix.clone().unwrap_or_default(),
        access_key_id,
        access_key_secret,
        skip_verify: oss.skip_verify,
        ca_cert_files: oss.ca_cert_files.clone(),
        timeout: DEFAULT_HTTP_TIMEOUT_SECS,
        connect_timeout: DEFAULT_HTTP_TIMEOUT_SECS,
        retry_limit: BACKEND_RETRY_LIMIT,
        proxy: Default::default(),
    };
    Ok(BackendConfigV2 {
        backend_type: "oss".to_string(),
        localdisk: None,
        localfs: None,
        oss: Some(oss_cfg),
        s3: None,
        registry: None,
        http_proxy: None,
    })
}

/// Normalise an object-store `endpoint` into `(scheme, bare_host)`.
///
/// The storage backends build the object URL as `{scheme}://{endpoint}/...`, so
/// `endpoint` must be a bare host with no scheme. If the operator nonetheless
/// wrote a scheme-prefixed URL (`http://` / `https://`), the explicit prefix is
/// stripped and wins over `insecure` (friendliest — a pasted URL still works,
/// and never produces a malformed `https://https://…`). Otherwise `insecure`
/// selects `http` vs `https`. A trailing `/` on the host is trimmed.
fn resolve_endpoint_scheme(endpoint: &str, insecure: bool) -> (String, String) {
    let (scheme, host) = if let Some(rest) = endpoint.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        ("http", rest)
    } else if insecure {
        ("http", endpoint)
    } else {
        ("https", endpoint)
    };
    (scheme.to_string(), host.trim_end_matches('/').to_string())
}

/// Build the `http-proxy` `BackendConfigV2`. The proxy `url` maps to the api
/// `addr`; the optional blob `path` prefix maps to `path` (empty when unset —
/// correct for a unix-socket proxy, which ignores it). TLS knobs (`skip_verify`
/// / `ca_cert_files`) map through for an HTTPS proxy served with a self-signed
/// / private CA cert.
fn build_http_proxy_backend(http_proxy: &HttpProxyBackendConfig) -> BackendConfigV2 {
    let http_proxy_cfg = HttpProxyConfig {
        addr: http_proxy.url.clone(),
        path: http_proxy.path.clone().unwrap_or_default(),
        skip_verify: http_proxy.skip_verify,
        ca_cert_files: http_proxy.ca_cert_files.clone(),
        timeout: DEFAULT_HTTP_TIMEOUT_SECS,
        connect_timeout: DEFAULT_HTTP_TIMEOUT_SECS,
        retry_limit: BACKEND_RETRY_LIMIT,
        proxy: Default::default(),
    };
    BackendConfigV2 {
        backend_type: "http-proxy".to_string(),
        localdisk: None,
        localfs: None,
        oss: None,
        s3: None,
        registry: None,
        http_proxy: Some(http_proxy_cfg),
    }
}

/// Resolve a credential from the environment variable named `var_name`. An
/// empty name means "no credential" (blank string). A non-empty name that is
/// not present in the environment is a hard error, so a misconfigured backend
/// fails loudly at daemon-config build time rather than at first blob fetch.
fn resolve_credential_env(var_name: &str) -> anyhow::Result<String> {
    if var_name.is_empty() {
        return Ok(String::new());
    }
    std::env::var(var_name).with_context(|| {
        format!("environment variable `{var_name}` referenced by a storage backend is not set")
    })
}

/// Build a `ConfigV2` for the **auto-accel sidecar** mount: a `localfs`
/// backend pointed at the symlinked gzip-layer / zran-index directory + a
/// `fanotify` pre-content cache pointed at the staging directory holding the
/// merged bootstrap.
///
/// This is the read-side of the node-local acceleration flow: gzip layers
/// (already in containerd's content store) appear in `backend_dir` as
/// symlinks keyed by their nydus blob ids; the merged RAFS v6 bootstrap and
/// per-layer zran index blobs live under the same `backend_dir`. The fanotify
/// handler stages EROFS device files as hardlinks to the blob cache files and
/// serves on-demand reads via `FAN_PRE_ACCESS`.
///
/// `daemon_mountpoint` is the FUSE mountpoint the snapshotter hands back to
/// containerd; the fanotify EROFS mount and the FUSE bind reuse it.
pub fn build_auto_accel_config(
    backend_dir: &Path,
    stage_dir: &Path,
    daemon_mountpoint: &Path,
    daemon_id: &str,
) -> ConfigV2 {
    let backend = BackendConfigV2 {
        backend_type: "localfs".to_string(),
        localdisk: None,
        localfs: Some(LocalFsConfig {
            blob_file: String::new(),
            dir: backend_dir.display().to_string(),
            alt_dirs: Vec::new(),
        }),
        oss: None,
        s3: None,
        registry: None,
        http_proxy: None,
    };

    let cache = CacheConfigV2 {
        cache_type: "fanotify".to_string(),
        cache_compressed: false,
        cache_validate: false,
        prefetch: Default::default(),
        file_cache: None,
        fanotify: Some(FanotifyConfig {
            work_dir: stage_dir.display().to_string(),
            mountpoint: daemon_mountpoint.display().to_string(),
        }),
    };

    let rafs = RafsConfigV2 {
        mode: "direct".to_string(),
        user_io_batch_size: 1024 * 1024,
        validate: false,
        enable_xattr: true,
        iostats_files: false,
        access_pattern: false,
        latest_read_files: false,
        prefetch: Default::default(),
    };

    ConfigV2 {
        version: 2,
        id: daemon_id.to_string(),
        backend: Some(backend),
        external_backends: Vec::new(),
        cache: Some(cache),
        rafs: Some(rafs),
        overlay: None,
        internal: Default::default(),
    }
}

/// Wrap an auto-accel `ConfigV2` + bootstrap in the `BlobCacheEntry` form the
/// fanotify pre-content path consumes (mirrors `build_blob_cache_entry` but
/// for the localfs+fanotify combo, not registry+filecache).
pub fn build_auto_accel_blob_cache_entry(
    backend_dir: &Path,
    stage_dir: &Path,
    daemon_mountpoint: &Path,
    daemon_id: &str,
    bootstrap: &Path,
) -> anyhow::Result<BlobCacheEntry> {
    let cfg_v2 = build_auto_accel_config(backend_dir, stage_dir, daemon_mountpoint, daemon_id);
    let entry_config = BlobCacheEntryConfigV2 {
        version: cfg_v2.version,
        id: cfg_v2.id,
        backend: cfg_v2.backend.unwrap_or_default(),
        external_backends: cfg_v2.external_backends,
        cache: cfg_v2.cache.unwrap_or_default(),
        metadata_path: Some(bootstrap.display().to_string()),
    };
    let value = json!({
        "type": BLOB_CACHE_TYPE_META_BLOB,
        "id": daemon_id,
        "domain_id": daemon_id,
        "config_v2": entry_config,
    });
    Ok(serde_json::from_value(value)?)
}

/// Build a blob-cache entry for service block-device export.
///
/// `BlobCacheEntry` has a crate-private legacy config field, so construct it
/// through serde using the public wire representation rather than relying on
/// field literals outside `nydus-api`.
pub fn build_blob_cache_entry(
    cfg: &SnapshotterConfig,
    image_ref: &ImageRef,
    cache_work_dir: &Path,
    auth: Option<String>,
    daemon_id: &str,
    bootstrap: &Path,
) -> anyhow::Result<BlobCacheEntry> {
    let cfg_v2 = build_daemon_config(cfg, image_ref, cache_work_dir, auth, daemon_id)?;
    let entry_config = BlobCacheEntryConfigV2 {
        version: cfg_v2.version,
        id: cfg_v2.id,
        backend: cfg_v2.backend.unwrap_or_default(),
        external_backends: cfg_v2.external_backends,
        cache: cfg_v2.cache.unwrap_or_default(),
        metadata_path: Some(bootstrap.display().to_string()),
    };
    let value = json!({
        "type": BLOB_CACHE_TYPE_META_BLOB,
        "id": daemon_id,
        "domain_id": daemon_id,
        "config_v2": entry_config,
    });
    Ok(serde_json::from_value(value)?)
}

fn parse_timeout_seconds(value: &str) -> u32 {
    let trimmed = value.trim();
    let parsed = if let Some(num) = trimmed.strip_suffix("ms") {
        // Round sub-second values UP to 1s: the storage backend treats a
        // timeout of 0 as "no timeout at all" (connection.rs maps 0 -> None),
        // so the old truncation turned an operator's fail-fast "500ms" into
        // an UNBOUNDED request timeout.
        num.parse::<u32>().ok().map(|n| n.div_ceil(1000).max(1))
    } else if let Some(num) = trimmed.strip_suffix('s') {
        num.parse::<u32>().ok()
    } else if let Some(num) = trimmed.strip_suffix('m') {
        num.parse::<u32>().ok().map(|n| n.saturating_mul(60))
    } else {
        trimmed.parse::<u32>().ok()
    };
    parsed.unwrap_or_else(|| {
        warn!(
            value,
            "unparseable timeout value; falling back to 30 seconds"
        );
        30
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::image_ref::parse_image_ref;
    use std::path::PathBuf;

    #[test]
    fn build_config_for_dockerhub_image() {
        let cfg = SnapshotterConfig::default();
        let image = parse_image_ref("docker.io/library/nginx:latest").unwrap();
        let cv2 = build_daemon_config(
            &cfg,
            &image,
            &PathBuf::from("/var/lib/containerd-nydus/cache/nginx"),
            Some("dXNlcjpwYXNz".to_string()),
            "test-daemon",
        )
        .unwrap();
        assert_eq!(cv2.version, 2);
        let backend = cv2.backend.as_ref().unwrap();
        assert_eq!(backend.backend_type, "registry");
        let reg = backend.registry.as_ref().unwrap();
        assert_eq!(reg.host, "registry-1.docker.io");
        assert_eq!(reg.repo, "library/nginx");
        assert_eq!(reg.auth.as_deref(), Some("dXNlcjpwYXNz"));
        let cache = cv2.cache.as_ref().unwrap();
        assert_eq!(cache.cache_type, "filecache");
        assert_eq!(
            cache.file_cache.as_ref().unwrap().work_dir,
            "/var/lib/containerd-nydus/cache/nginx"
        );
        assert!(cv2.validate());
    }

    #[test]
    fn build_blob_cache_entry_for_blockdev_export() {
        let cfg = SnapshotterConfig::default();
        let image = parse_image_ref("docker.io/library/nginx:latest").unwrap();
        let entry = build_blob_cache_entry(
            &cfg,
            &image,
            &PathBuf::from("/var/lib/containerd-nydus/cache/nginx"),
            None,
            "test-daemon",
            &PathBuf::from("/var/lib/containerd-nydus/bootstrap/image.boot"),
        )
        .unwrap();

        assert_eq!(entry.blob_type, BLOB_CACHE_TYPE_META_BLOB);
        assert_eq!(entry.blob_id, "test-daemon");
        assert_eq!(entry.domain_id, "test-daemon");
        let config = entry.blob_config.as_ref().unwrap();
        assert_eq!(config.id, "test-daemon");
        assert_eq!(
            config.metadata_path.as_deref(),
            Some("/var/lib/containerd-nydus/bootstrap/image.boot")
        );
        assert_eq!(config.backend.backend_type, "registry");
        assert_eq!(config.cache.cache_type, "filecache");
    }

    #[test]
    fn timeout_parsing() {
        assert_eq!(parse_timeout_seconds("30s"), 30);
        assert_eq!(parse_timeout_seconds("2m"), 120);
        assert_eq!(parse_timeout_seconds("45"), 45);
        assert_eq!(parse_timeout_seconds("garbage"), 30);
        // Sub-second values must round UP to 1s, never to 0 (0 = no timeout in
        // the storage backend), so "fail fast" cannot become "wait forever".
        assert_eq!(parse_timeout_seconds("500ms"), 1);
        assert_eq!(parse_timeout_seconds("1ms"), 1);
        assert_eq!(parse_timeout_seconds("1500ms"), 2);
        assert_eq!(parse_timeout_seconds("2000ms"), 2);
    }

    // ── B3: backend selection + s3/oss/http-proxy mapping ──────────────

    use crate::config::{
        HttpProxyBackendConfig, OssBackendConfig, RegistryBackendConfig, S3BackendConfig,
    };

    fn dummy_image() -> ImageRef {
        parse_image_ref("docker.io/library/nginx:latest").unwrap()
    }

    #[test]
    fn no_backend_section_defaults_to_registry() {
        // Empty [backends] ⇒ the image's own registry drives the daemon.
        let cfg = SnapshotterConfig::default();
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        assert_eq!(backend.backend_type, "registry");
        assert!(backend.registry.is_some());
        assert!(backend.s3.is_none() && backend.oss.is_none() && backend.http_proxy.is_none());
    }

    #[test]
    fn registry_backend_maps_plain_http_and_skip_verify() {
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.registry = Some(RegistryBackendConfig {
            mirrors: Vec::new(),
            skip_verify: true,
            ca_cert_files: Vec::new(),
            plain_http: true,
            request_timeout: "45s".to_string(),
        });
        let backend =
            build_backend_config(&cfg, &dummy_image(), Some("dXNlcjpwYXNz".to_string())).unwrap();
        assert_eq!(backend.backend_type, "registry");
        let reg = backend.registry.as_ref().unwrap();
        assert_eq!(reg.scheme, "http");
        assert!(reg.skip_verify);
        assert_eq!(reg.timeout, 45);
        assert_eq!(reg.connect_timeout, 45);
        assert_eq!(reg.auth.as_deref(), Some("dXNlcjpwYXNz"));
    }

    #[test]
    fn registry_backend_maps_ca_cert_files() {
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.registry = Some(RegistryBackendConfig {
            mirrors: Vec::new(),
            skip_verify: false,
            ca_cert_files: vec!["/etc/ca.pem".to_string()],
            plain_http: false,
            request_timeout: "30s".to_string(),
        });
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        let reg = backend.registry.as_ref().unwrap();
        assert_eq!(reg.ca_cert_files, vec!["/etc/ca.pem".to_string()]);
        assert!(!reg.skip_verify);
    }

    /// Build an `S3BackendConfig` with the given endpoint/insecure/object_prefix
    /// and no credentials, for the scheme/prefix mapping tests.
    fn s3_cfg(endpoint: &str, insecure: bool, object_prefix: Option<&str>) -> S3BackendConfig {
        S3BackendConfig {
            endpoint: endpoint.to_string(),
            region: "us-east-1".to_string(),
            bucket: "b".to_string(),
            access_key_env: String::new(),
            secret_key_env: String::new(),
            insecure,
            object_prefix: object_prefix.map(str::to_string),
            skip_verify: false,
            ca_cert_files: Vec::new(),
        }
    }

    #[test]
    fn s3_backend_maps_fields_and_resolves_env_credentials() {
        // Unique env var names to avoid cross-test interference.
        unsafe {
            std::env::set_var("B3_TEST_S3_AK", "AKIAEXAMPLE");
            std::env::set_var("B3_TEST_S3_SK", "s3cr3t");
        }
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.s3 = Some(S3BackendConfig {
            // Bare host — the required form; scheme comes from `insecure`.
            endpoint: "s3.us-east-1.amazonaws.com".to_string(),
            region: "us-east-1".to_string(),
            bucket: "my-nydus-blobs".to_string(),
            access_key_env: "B3_TEST_S3_AK".to_string(),
            secret_key_env: "B3_TEST_S3_SK".to_string(),
            insecure: false,
            object_prefix: Some("nydus/".to_string()),
            skip_verify: false,
            ca_cert_files: Vec::new(),
        });
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        assert_eq!(backend.backend_type, "s3");
        assert!(backend.registry.is_none());
        let s3 = backend.s3.as_ref().unwrap();
        assert_eq!(s3.endpoint, "s3.us-east-1.amazonaws.com");
        assert_eq!(s3.scheme, "https");
        assert_eq!(s3.region, "us-east-1");
        assert_eq!(s3.bucket_name, "my-nydus-blobs");
        assert_eq!(s3.object_prefix, "nydus/");
        assert_eq!(s3.access_key_id, "AKIAEXAMPLE");
        assert_eq!(s3.access_key_secret, "s3cr3t");
        assert_eq!(s3.retry_limit, BACKEND_RETRY_LIMIT);
        // The mapped backend must pass nydus-api's own validator.
        let bc = BackendConfigV2 {
            backend_type: "s3".to_string(),
            s3: backend.s3.clone(),
            ..Default::default()
        };
        assert!(bc.validate());
        unsafe {
            std::env::remove_var("B3_TEST_S3_AK");
            std::env::remove_var("B3_TEST_S3_SK");
        }
    }

    #[test]
    fn s3_bare_host_insecure_selects_http_scheme() {
        // Bare MinIO host + insecure ⇒ http, endpoint stays the bare host.
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.s3 = Some(s3_cfg("minio.local:9000", true, None));
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        let s3 = backend.s3.as_ref().unwrap();
        assert_eq!(s3.scheme, "http");
        assert_eq!(s3.endpoint, "minio.local:9000");
        assert_eq!(s3.object_prefix, "");
    }

    #[test]
    fn s3_scheme_prefixed_endpoint_is_stripped_not_malformed() {
        // REGRESSION: a scheme-prefixed endpoint used to produce a malformed
        // `https://https://…`. The prefix must be stripped and win over the
        // `insecure` flag; the stored endpoint is a bare host.
        for (endpoint, insecure, want_scheme) in [
            ("https://s3.us-east-1.amazonaws.com", false, "https"),
            ("http://minio.local:9000", false, "http"), // prefix wins over insecure=false
            ("https://s3.example.com", true, "https"),  // prefix wins over insecure=true
            ("https://s3.example.com/", false, "https"), // trailing slash trimmed
        ] {
            let mut cfg = SnapshotterConfig::default();
            cfg.backends.s3 = Some(s3_cfg(endpoint, insecure, None));
            let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
            let s3 = backend.s3.as_ref().unwrap();
            assert_eq!(s3.scheme, want_scheme, "scheme for {endpoint}");
            assert!(
                !s3.endpoint.contains("://"),
                "endpoint must be a bare host, got {:?}",
                s3.endpoint
            );
            // The reconstructed URL prefix must be well-formed (no double scheme).
            let url = format!("{}://{}", s3.scheme, s3.endpoint);
            assert!(
                url.matches("://").count() == 1,
                "reconstructed URL must have exactly one scheme separator: {url}"
            );
        }
    }

    #[test]
    fn s3_backend_missing_env_var_is_hard_error() {
        let mut cfg = SnapshotterConfig::default();
        let mut s3 = s3_cfg("s3.example.com", false, None);
        s3.access_key_env = "B3_TEST_DEFINITELY_UNSET_VAR".to_string();
        s3.secret_key_env = "B3_TEST_DEFINITELY_UNSET_VAR_2".to_string();
        cfg.backends.s3 = Some(s3);
        let err = build_backend_config(&cfg, &dummy_image(), None).unwrap_err();
        assert!(
            err.to_string().contains("B3_TEST_DEFINITELY_UNSET_VAR"),
            "error should name the missing env var: {err}"
        );
    }

    #[test]
    fn oss_backend_maps_fields_anonymous_with_scheme_and_prefix() {
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.oss = Some(OssBackendConfig {
            endpoint: "oss-cn-hangzhou.aliyuncs.com".to_string(),
            bucket: "nydus-bucket".to_string(),
            access_key_env: String::new(),
            secret_key_env: String::new(),
            insecure: false,
            object_prefix: Some("blobs/".to_string()),
            skip_verify: false,
            ca_cert_files: Vec::new(),
        });
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        assert_eq!(backend.backend_type, "oss");
        let oss = backend.oss.as_ref().unwrap();
        assert_eq!(oss.endpoint, "oss-cn-hangzhou.aliyuncs.com");
        assert_eq!(oss.scheme, "https");
        assert_eq!(oss.bucket_name, "nydus-bucket");
        assert_eq!(oss.object_prefix, "blobs/");
        assert_eq!(oss.access_key_id, "");
        assert_eq!(oss.access_key_secret, "");
        let bc = BackendConfigV2 {
            backend_type: "oss".to_string(),
            oss: backend.oss.clone(),
            ..Default::default()
        };
        assert!(bc.validate());
    }

    #[test]
    fn oss_scheme_prefixed_endpoint_is_stripped() {
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.oss = Some(OssBackendConfig {
            endpoint: "http://oss.local:9000".to_string(),
            bucket: "b".to_string(),
            access_key_env: String::new(),
            secret_key_env: String::new(),
            insecure: false,
            object_prefix: None,
            skip_verify: false,
            ca_cert_files: Vec::new(),
        });
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        let oss = backend.oss.as_ref().unwrap();
        assert_eq!(oss.scheme, "http");
        assert_eq!(oss.endpoint, "oss.local:9000");
    }

    #[test]
    fn s3_backend_maps_skip_verify_and_ca_cert_files() {
        let mut cfg = SnapshotterConfig::default();
        let mut s3 = s3_cfg("s3.example.com", false, None);
        s3.skip_verify = true;
        s3.ca_cert_files = vec!["/etc/s3-ca.pem".to_string()];
        cfg.backends.s3 = Some(s3);
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        let s3c = backend.s3.as_ref().unwrap();
        assert!(s3c.skip_verify);
        assert_eq!(s3c.ca_cert_files, vec!["/etc/s3-ca.pem".to_string()]);
        // The TLS-configured backend must still pass nydus-api's validator.
        let bc = BackendConfigV2 {
            backend_type: "s3".to_string(),
            s3: backend.s3.clone(),
            ..Default::default()
        };
        assert!(bc.validate());
    }

    #[test]
    fn oss_backend_maps_skip_verify_and_ca_cert_files() {
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.oss = Some(OssBackendConfig {
            endpoint: "oss-cn-hangzhou.aliyuncs.com".to_string(),
            bucket: "b".to_string(),
            access_key_env: String::new(),
            secret_key_env: String::new(),
            insecure: false,
            object_prefix: None,
            skip_verify: true,
            ca_cert_files: vec!["/etc/oss-ca.pem".to_string()],
        });
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        let oss = backend.oss.as_ref().unwrap();
        assert!(oss.skip_verify);
        assert_eq!(oss.ca_cert_files, vec!["/etc/oss-ca.pem".to_string()]);
        let bc = BackendConfigV2 {
            backend_type: "oss".to_string(),
            oss: backend.oss.clone(),
            ..Default::default()
        };
        assert!(bc.validate());
    }

    #[test]
    fn http_proxy_backend_maps_url_to_addr() {
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.http_proxy = Some(HttpProxyBackendConfig {
            url: "http://127.0.0.1:8000".to_string(),
            path: None,
            skip_verify: false,
            ca_cert_files: Vec::new(),
        });
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        assert_eq!(backend.backend_type, "http-proxy");
        let hp = backend.http_proxy.as_ref().unwrap();
        assert_eq!(hp.addr, "http://127.0.0.1:8000");
        // Default (no path) maps to an empty path prefix.
        assert_eq!(hp.path, "");
        assert!(!hp.skip_verify);
        assert!(hp.ca_cert_files.is_empty());
        assert_eq!(hp.retry_limit, BACKEND_RETRY_LIMIT);
        let bc = BackendConfigV2 {
            backend_type: "http-proxy".to_string(),
            http_proxy: backend.http_proxy.clone(),
            ..Default::default()
        };
        assert!(bc.validate());
    }

    #[test]
    fn http_proxy_backend_maps_path_and_tls_knobs() {
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.http_proxy = Some(HttpProxyBackendConfig {
            url: "https://proxy.example.com".to_string(),
            path: Some("/blobs".to_string()),
            skip_verify: true,
            ca_cert_files: vec!["/etc/proxy-ca.pem".to_string()],
        });
        let backend = build_backend_config(&cfg, &dummy_image(), None).unwrap();
        let hp = backend.http_proxy.as_ref().unwrap();
        assert_eq!(hp.addr, "https://proxy.example.com");
        assert_eq!(hp.path, "/blobs");
        assert!(hp.skip_verify);
        assert_eq!(hp.ca_cert_files, vec!["/etc/proxy-ca.pem".to_string()]);
        let bc = BackendConfigV2 {
            backend_type: "http-proxy".to_string(),
            http_proxy: backend.http_proxy.clone(),
            ..Default::default()
        };
        assert!(bc.validate());
    }

    #[test]
    fn s3_full_config_is_valid() {
        // build_daemon_config wraps the selected backend with cache + rafs; the
        // whole ConfigV2 must validate against nydus-api.
        let mut cfg = SnapshotterConfig::default();
        cfg.backends.s3 = Some(s3_cfg("s3.example.com", false, None));
        let cv2 = build_daemon_config(
            &cfg,
            &dummy_image(),
            &PathBuf::from("/var/lib/containerd-nydus/cache/x"),
            None,
            "test-daemon",
        )
        .unwrap();
        assert_eq!(cv2.backend.as_ref().unwrap().backend_type, "s3");
        assert_eq!(cv2.cache.as_ref().unwrap().cache_type, "filecache");
        assert!(cv2.validate());
    }

    #[test]
    fn resolve_endpoint_scheme_matrix() {
        assert_eq!(
            resolve_endpoint_scheme("s3.example.com", false),
            ("https".to_string(), "s3.example.com".to_string())
        );
        assert_eq!(
            resolve_endpoint_scheme("s3.example.com", true),
            ("http".to_string(), "s3.example.com".to_string())
        );
        assert_eq!(
            resolve_endpoint_scheme("https://s3.example.com", true),
            ("https".to_string(), "s3.example.com".to_string())
        );
        assert_eq!(
            resolve_endpoint_scheme("http://minio.local:9000/", false),
            ("http".to_string(), "minio.local:9000".to_string())
        );
    }
}
