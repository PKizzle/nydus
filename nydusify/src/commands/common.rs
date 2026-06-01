// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::cli::BackendType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkDictReference {
    pub format: String,
    pub source: String,
    pub reference: String,
}

pub fn add_reference_suffix(source: &str, suffix: &str) -> Result<String> {
    if source.contains('@') {
        bail!("unsupported digested image reference `{source}` when --target-suffix is used");
    }
    if suffix.is_empty() {
        bail!("--target-suffix must not be empty");
    }

    let last_path_component = source.rsplit('/').next().unwrap_or(source);
    if last_path_component.contains(':') {
        Ok(format!("{source}{suffix}"))
    } else {
        Ok(format!("{source}:latest{suffix}"))
    }
}

pub fn resolve_backend_config(
    backend_type: Option<BackendType>,
    inline_config: Option<&str>,
    config_file: Option<&Path>,
    flag_prefix: &str,
) -> Result<Option<String>> {
    if inline_config.is_some() && config_file.is_some() {
        bail!("--{flag_prefix}backend-config conflicts with --{flag_prefix}backend-config-file");
    }

    let config = match (inline_config, config_file) {
        (Some(config), None) => Some(config.to_string()),
        (None, Some(path)) => Some(
            fs::read_to_string(path)
                .with_context(|| format!("read backend config file {}", path.display()))?,
        ),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!(),
    };

    if backend_type.is_none() && config.is_some() {
        bail!("--{flag_prefix}backend-type is required when backend configuration is provided");
    }

    if let Some(kind) = backend_type
        && kind != BackendType::Registry
        && config.as_deref().unwrap_or_default().trim().is_empty()
    {
        bail!(
            "backend configuration is empty, please specify option '--{flag_prefix}backend-config'"
        );
    }

    Ok(config)
}

pub fn validate_platform_selection(all_platforms: bool, platform: Option<&str>) -> Result<()> {
    if all_platforms && platform.is_some() {
        bail!("--all-platforms conflicts with --platform");
    }
    Ok(())
}

/// Resolve the effective target platform, falling back to the host platform
/// when `--platform` was not explicitly provided.
pub fn resolve_platform(platform: Option<&str>) -> String {
    platform
        .map(str::to_string)
        .unwrap_or_else(crate::cli::default_platform)
}

pub fn validate_existing_file(path: &Path, flag_name: &str) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("{flag_name} is not accessible: {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "{flag_name} must point to a regular file: {}",
            path.display()
        );
    }
    Ok(())
}

pub fn validate_output_parent_dir(path: &Path, flag_name: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let metadata = fs::metadata(&parent).with_context(|| {
        format!(
            "{flag_name} parent directory is not accessible: {}",
            parent.display()
        )
    })?;
    if !metadata.is_dir() {
        bail!(
            "{flag_name} parent path is not a directory: {}",
            parent.display()
        );
    }
    Ok(())
}

pub fn parse_chunk_dict_reference(value: &str) -> Result<ChunkDictReference> {
    let mut parts = value.splitn(3, ':');
    let format = parts.next().unwrap_or_default();
    let source = parts.next().unwrap_or_default();
    let reference = parts.next().unwrap_or_default();

    if format != "bootstrap" {
        bail!("invalid chunk dict format {format}, should be [bootstrap]");
    }
    if !matches!(source, "registry" | "local") {
        bail!("invalid chunk dict source {source}, should be [registry, local]");
    }
    if reference.is_empty() {
        bail!("invalid chunk dict reference");
    }

    Ok(ChunkDictReference {
        format: format.to_string(),
        source: source.to_string(),
        reference: reference.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::default_platform;

    #[test]
    fn suffix_rejects_digest_reference() {
        let err = add_reference_suffix("example.com/app@sha256:abc", "-nydus").unwrap_err();
        assert!(err.to_string().contains("digested image reference"));
    }

    #[test]
    fn suffix_preserves_tag() {
        let target = add_reference_suffix("localhost:5000/app:1", "-nydus").unwrap();
        assert_eq!(target, "localhost:5000/app:1-nydus");
    }

    #[test]
    fn suffix_adds_latest_for_untagged_reference() {
        let target = add_reference_suffix("localhost:5000/app", "-nydus").unwrap();
        assert_eq!(target, "localhost:5000/app:latest-nydus");
    }

    #[test]
    fn parses_registry_chunk_dict_reference_with_tag_colons() {
        let parsed = parse_chunk_dict_reference("bootstrap:registry:localhost:5000/app:dict")
            .expect("chunk dict ref should parse");

        assert_eq!(parsed.format, "bootstrap");
        assert_eq!(parsed.source, "registry");
        assert_eq!(parsed.reference, "localhost:5000/app:dict");
    }

    #[test]
    fn validates_archive_parent_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let target_archive = temp_dir.path().join("image.tar");

        validate_output_parent_dir(&target_archive, "--target-archive").unwrap();
    }

    #[test]
    fn resolves_registry_backend_without_inline_config() {
        let config = resolve_backend_config(Some(BackendType::Registry), None, None, "").unwrap();

        assert!(config.is_none());
    }

    #[test]
    fn rejects_backend_config_without_backend_type() {
        let err = resolve_backend_config(None, Some("{}"), None, "source-").unwrap_err();

        assert!(
            err.to_string()
                .contains("--source-backend-type is required")
        );
    }

    #[test]
    fn rejects_non_registry_backend_without_config() {
        let err =
            resolve_backend_config(Some(BackendType::Oss), None, None, "target-").unwrap_err();

        assert!(err.to_string().contains("--target-backend-config"));
    }

    #[test]
    fn rejects_platform_conflict() {
        let err = validate_platform_selection(true, Some("linux/amd64")).unwrap_err();

        assert!(
            err.to_string()
                .contains("--all-platforms conflicts with --platform")
        );
    }

    #[test]
    fn rejects_all_platforms_with_explicit_host_default_platform() {
        // Regression: explicitly passing the host-default platform alongside
        // --all-platforms must still be reported as a conflict.
        let err = validate_platform_selection(true, Some(&default_platform())).unwrap_err();

        assert!(
            err.to_string()
                .contains("--all-platforms conflicts with --platform")
        );
    }

    #[test]
    fn accepts_all_platforms_without_explicit_platform() {
        assert!(validate_platform_selection(true, None).is_ok());
    }

    #[test]
    fn resolves_platform_default_when_absent() {
        assert_eq!(resolve_platform(None), default_platform());
        assert_eq!(resolve_platform(Some("linux/arm64")), "linux/arm64");
    }

    #[test]
    fn rejects_chunk_dict_with_invalid_format() {
        let err = parse_chunk_dict_reference("manifest:registry:localhost/app:dict").unwrap_err();
        assert!(err.to_string().contains("invalid chunk dict format"));
    }

    #[test]
    fn rejects_chunk_dict_with_invalid_source() {
        let err = parse_chunk_dict_reference("bootstrap:http:localhost/app:dict").unwrap_err();
        assert!(err.to_string().contains("invalid chunk dict source"));
    }

    #[test]
    fn rejects_chunk_dict_without_reference() {
        let err = parse_chunk_dict_reference("bootstrap:registry:").unwrap_err();
        assert!(err.to_string().contains("invalid chunk dict reference"));
    }
}
