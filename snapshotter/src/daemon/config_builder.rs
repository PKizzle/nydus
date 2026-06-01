// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Build a `nydus_api::ConfigV2` JSON document for an in-process FUSE daemon.
//!
//! Mirrors the JSON the Go snapshotter would emit before calling nydusd, but
//! constructed programmatically from the unified TOML config + per-image
//! parameters (image reference, cache directory, auth).

use std::path::Path;

use nydus_api::{
    BLOB_CACHE_TYPE_META_BLOB, BackendConfigV2, BlobCacheEntry, BlobCacheEntryConfigV2,
    CacheConfigV2, ConfigV2, FileCacheConfig, RafsConfigV2, RegistryConfig,
};
use serde_json::json;

use crate::config::SnapshotterConfig;
use crate::daemon::image_ref::ImageRef;

/// Build a `ConfigV2` for the registry backend + filecache pair.
///
/// `cache_work_dir` is the per-image directory that nydusd uses to materialise
/// chunk caches. `auth` is the optional `base64(user:password)` blob from the
/// configured pull-auth environment variable.
pub fn build_registry_config(
    cfg: &SnapshotterConfig,
    image_ref: &ImageRef,
    cache_work_dir: &Path,
    auth: Option<String>,
    daemon_id: &str,
) -> ConfigV2 {
    let registry_cfg = cfg.backends.registry.as_ref();
    let timeout_secs = parse_timeout_seconds(
        registry_cfg
            .map(|c| c.request_timeout.as_str())
            .unwrap_or("30s"),
    );
    let registry = RegistryConfig {
        scheme: "https".to_string(),
        host: image_ref.api_host.clone(),
        repo: image_ref.repo.clone(),
        auth,
        skip_verify: registry_cfg.map(|c| c.skip_verify).unwrap_or(false),
        ca_cert_files: Vec::new(),
        timeout: timeout_secs,
        connect_timeout: timeout_secs,
        retry_limit: 3,
        registry_token: None,
        blob_url_scheme: String::new(),
        blob_redirected_host: String::new(),
        proxy: Default::default(),
    };

    let backend = BackendConfigV2 {
        backend_type: "registry".to_string(),
        localdisk: None,
        localfs: None,
        oss: None,
        s3: None,
        registry: Some(registry),
        http_proxy: None,
    };

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
    let cfg_v2 = build_registry_config(cfg, image_ref, cache_work_dir, auth, daemon_id);
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
    let value = value.trim();
    if let Some(num) = value.strip_suffix("ms") {
        return num.parse::<u32>().map(|n| n.max(1) / 1000).unwrap_or(30);
    }
    if let Some(num) = value.strip_suffix('s') {
        return num.parse::<u32>().unwrap_or(30);
    }
    if let Some(num) = value.strip_suffix('m') {
        return num
            .parse::<u32>()
            .map(|n| n.saturating_mul(60))
            .unwrap_or(30);
    }
    value.parse::<u32>().unwrap_or(30)
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
        let cv2 = build_registry_config(
            &cfg,
            &image,
            &PathBuf::from("/var/lib/containerd-nydus/cache/nginx"),
            Some("dXNlcjpwYXNz".to_string()),
            "test-daemon",
        );
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
    }
}
