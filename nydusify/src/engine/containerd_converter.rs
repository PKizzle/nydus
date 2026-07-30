// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Containerd-converter compatible request layer for nydusify-rs.
//!
//! The Go implementation routes conversion through Harbor's
//! acceleration-service wrapper and a snapshotter-converter driver. This
//! module models the same provider + `nydus` driver contract without
//! depending on the acceleration-service package; [`ImageConverter`]
//! dispatches to the conversion pipeline in [`crate::engine::converter`].

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tempfile::{Builder, TempDir};
use tracing::info;

use crate::cli::{BackendType, ConvertArgs};
use crate::commands::common::{parse_chunk_dict_reference, resolve_backend_config};
use crate::commands::convert::{ConversionMode, ConvertPlan, SourceSpec};

/// Converter backend contract. `convert` is an `async fn` in the trait (AFIT);
/// the single implementor ([`ContainerdConverter`]) is dispatched statically,
/// so no `Send` bound is required and the `!Send` compio registry client can be
/// held directly across awaits.
#[allow(async_fn_in_trait)]
pub trait ImageConverter {
    async fn convert(&self, request: ConvertRequest) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
pub struct ContainerdConverter;

impl ImageConverter for ContainerdConverter {
    async fn convert(&self, request: ConvertRequest) -> Result<()> {
        let workspace = request.prepare_workspace()?;
        info!(
            source = %request.source,
            target = %request.target,
            tmp_dir = %workspace.path().display(),
            driver = "nydus",
            mode = ?request.mode,
            oci_ref = request.driver.oci_ref,
            "prepared containerd-converter request"
        );

        crate::engine::converter::run_conversion(&request, workspace.path()).await
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConvertRequest {
    /// The image reference the conversion is anchored to (the uppermost image `--source`).
    pub source: String,
    /// Every `--source` in stacking order, lowest first. One entry is the ordinary
    /// single-image conversion; more than one stacks directories and images together.
    pub sources: Vec<SourceSpec>,
    pub source_archive: Option<PathBuf>,
    pub target: String,
    pub target_archive: Option<PathBuf>,
    pub mode: ConversionMode,
    pub source_insecure: bool,
    pub target_insecure: bool,
    pub ca_cert_files: Vec<PathBuf>,
    pub source_backend_type: Option<String>,
    pub source_backend_config: Option<String>,
    pub all_platforms: bool,
    pub platforms: String,
    pub push_retry_count: u32,
    pub push_retry_delay: String,
    /// Plain HTTP is per-side: the two ends can legitimately disagree (an HTTPS
    /// upstream converted into a local HTTP test registry, say). `--plain-http`
    /// is folded into both here.
    pub source_plain_http: bool,
    pub target_plain_http: bool,
    pub work_dir: PathBuf,
    pub output_json: Option<PathBuf>,
    pub driver: NydusDriverConfig,
}

impl ConvertRequest {
    pub fn from_convert_args(
        args: &ConvertArgs,
        plan: &ConvertPlan,
        prefetch_patterns: String,
    ) -> Result<Self> {
        let backend_config = resolve_backend_config(
            args.backend_type,
            args.backend_config.as_deref(),
            args.backend_config_file.as_deref(),
            "",
        )?;
        let chunk_dict_ref = match &args.chunk_dict {
            Some(value) => Some(parse_chunk_dict_reference(value)?.reference),
            None => None,
        };

        Ok(Self {
            source: plan.source.clone(),
            sources: plan.sources.clone(),
            source_archive: args.source_archive.clone(),
            target: plan.target.clone(),
            target_archive: args.target_archive.clone(),
            mode: plan.mode,
            source_insecure: args.source_insecure,
            target_insecure: args.target_insecure,
            ca_cert_files: args.ca_cert.clone(),
            source_backend_type: args
                .source_backend_type
                .map(BackendType::as_str)
                .map(str::to_string),
            source_backend_config: resolve_backend_config(
                args.source_backend_type,
                args.source_backend_config.as_deref(),
                args.source_backend_config_file.as_deref(),
                "source-",
            )?,
            all_platforms: args.all_platforms,
            platforms: crate::commands::common::resolve_platform(args.platform.as_deref()),
            push_retry_count: args.push_retry_count,
            push_retry_delay: args.push_retry_delay.clone(),
            source_plain_http: args.plain_http || args.source_plain_http,
            target_plain_http: args.plain_http || args.target_plain_http,
            work_dir: args.work_dir.clone(),
            output_json: args.output_json.clone(),
            driver: NydusDriverConfig {
                work_dir: args.work_dir.clone(),
                builder: args.nydus_image.clone(),
                backend_type: args
                    .backend_type
                    .map(BackendType::as_str)
                    .unwrap_or_default()
                    .to_string(),
                backend_config: backend_config.unwrap_or_default(),
                backend_force_push: args.backend_force_push,
                chunk_dict_ref: chunk_dict_ref.unwrap_or_default(),
                docker2oci: plan.effective_oci,
                merge_manifest: args.merge_platform,
                oci_ref: plan.oci_ref,
                with_referrer: args.with_referrer,
                prefetch_patterns,
                prefetch_pattern_file: args.prefetch_pattern_file.clone(),
                compressor: args.compressor.clone(),
                fs_version: plan.fs_version.clone(),
                fs_align_chunk: args.fs_align_chunk || args.backend_aligned_chunk,
                fs_chunk_size: args.fs_chunk_size.clone(),
                batch_size: args.batch_size.clone(),
                cache_ref: args.build_cache.clone().unwrap_or_default(),
                cache_version: args.build_cache_version.clone(),
                cache_max_records: args.build_cache_max_records,
            },
        })
    }

    pub fn prepare_workspace(&self) -> Result<PreparedWorkspace> {
        ensure_work_dir(&self.work_dir)?;
        let temp_dir = Builder::new()
            .prefix("nydusify-")
            .tempdir_in(&self.work_dir)
            .with_context(|| {
                format!("create temporary directory in {}", self.work_dir.display())
            })?;
        Ok(PreparedWorkspace { temp_dir })
    }
}

#[derive(Debug)]
pub struct PreparedWorkspace {
    temp_dir: TempDir,
}

impl PreparedWorkspace {
    pub fn path(&self) -> &Path {
        self.temp_dir.path()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NydusDriverConfig {
    pub work_dir: PathBuf,
    pub builder: PathBuf,
    pub backend_type: String,
    pub backend_config: String,
    pub backend_force_push: bool,
    pub chunk_dict_ref: String,
    pub docker2oci: bool,
    pub merge_manifest: bool,
    pub oci_ref: bool,
    pub with_referrer: bool,
    pub prefetch_patterns: String,
    /// Access-pattern document handed to `nydus-image optimize` verbatim, when
    /// `--prefetch-pattern-file` was given. Takes precedence over
    /// `prefetch_patterns`, which cannot express per-file byte ranges.
    pub prefetch_pattern_file: Option<PathBuf>,
    pub compressor: String,
    pub fs_version: String,
    pub fs_align_chunk: bool,
    pub fs_chunk_size: String,
    pub batch_size: String,
    pub cache_ref: String,
    pub cache_version: String,
    pub cache_max_records: u32,
}

impl NydusDriverConfig {
    pub fn as_driver_map(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("work_dir".to_string(), self.work_dir.display().to_string()),
            ("builder".to_string(), self.builder.display().to_string()),
            ("backend_type".to_string(), self.backend_type.clone()),
            ("backend_config".to_string(), self.backend_config.clone()),
            (
                "backend_force_push".to_string(),
                self.backend_force_push.to_string(),
            ),
            ("chunk_dict_ref".to_string(), self.chunk_dict_ref.clone()),
            ("docker2oci".to_string(), self.docker2oci.to_string()),
            (
                "merge_manifest".to_string(),
                self.merge_manifest.to_string(),
            ),
            ("oci_ref".to_string(), self.oci_ref.to_string()),
            ("with_referrer".to_string(), self.with_referrer.to_string()),
            (
                "prefetch_patterns".to_string(),
                self.prefetch_patterns.clone(),
            ),
            (
                "prefetch_pattern_file".to_string(),
                self.prefetch_pattern_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
            ),
            ("compressor".to_string(), self.compressor.clone()),
            ("fs_version".to_string(), self.fs_version.clone()),
            (
                "fs_align_chunk".to_string(),
                self.fs_align_chunk.to_string(),
            ),
            ("fs_chunk_size".to_string(), self.fs_chunk_size.clone()),
            ("batch_size".to_string(), self.batch_size.clone()),
            ("cache_ref".to_string(), self.cache_ref.clone()),
            ("cache_version".to_string(), self.cache_version.clone()),
            (
                "cache_max_records".to_string(),
                self.cache_max_records.to_string(),
            ),
        ])
    }
}

fn ensure_work_dir(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => bail!("work directory {} is not a directory", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(path)
            .with_context(|| format!("create work directory {}", path.display())),
        Err(err) => Err(err).with_context(|| format!("stat work directory {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use crate::commands::convert::{PrefetchInput, plan};
    use clap::Parser;

    #[test]
    fn builds_go_compatible_nydus_driver_map_for_oci_ref() {
        let temp_dir = tempfile::tempdir().unwrap();
        let work_dir = temp_dir.path().join("work");
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target-suffix",
            "-nydus-oci-ref",
            "--oci-ref",
            "--with-referrer",
            "--work-dir",
            work_dir.to_str().unwrap(),
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };
        let plan = plan(&args).unwrap();
        assert_eq!(plan.prefetch, PrefetchInput::Root);
        assert_eq!(plan.mode, ConversionMode::Forward);

        let request = ConvertRequest::from_convert_args(&args, &plan, "/".to_string()).unwrap();
        let driver = request.driver.as_driver_map();

        assert_eq!(driver["builder"], "nydus-image");
        assert_eq!(driver["docker2oci"], "true");
        assert_eq!(driver["oci_ref"], "true");
        assert_eq!(driver["with_referrer"], "true");
        assert_eq!(driver["prefetch_patterns"], "/");
        assert_eq!(driver["fs_version"], "6");
        assert_eq!(driver["compressor"], "zstd");
    }

    #[test]
    fn prepares_temporary_workspace_under_requested_work_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let work_dir = temp_dir.path().join("missing-work-dir");
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target",
            "registry.local/app:nydus",
            "--work-dir",
            work_dir.to_str().unwrap(),
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };
        let plan = plan(&args).unwrap();
        let request = ConvertRequest::from_convert_args(&args, &plan, "/".to_string()).unwrap();

        let workspace = request.prepare_workspace().unwrap();

        assert!(work_dir.is_dir());
        assert!(workspace.path().starts_with(&work_dir));
        assert!(workspace.path().is_dir());
    }

    /// Build a ConvertRequest from bare `nydusify convert` args plus `extra`.
    fn request_with(extra: &[&str]) -> ConvertRequest {
        let temp_dir = tempfile::tempdir().unwrap();
        let work_dir = temp_dir.path().join("work");
        let mut argv = vec![
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target",
            "localhost:5000/app:nydus",
            "--work-dir",
            work_dir.to_str().unwrap(),
        ];
        argv.extend_from_slice(extra);
        let cli = Cli::parse_from(argv);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };
        let plan = plan(&args).unwrap();
        ConvertRequest::from_convert_args(&args, &plan, "/".to_string()).unwrap()
    }

    #[test]
    fn plain_http_defaults_to_https_on_both_sides() {
        let request = request_with(&[]);
        assert!(!request.source_plain_http);
        assert!(!request.target_plain_http);
    }

    #[test]
    fn plain_http_shorthand_covers_both_sides() {
        let request = request_with(&["--plain-http"]);
        assert!(request.source_plain_http);
        assert!(request.target_plain_http);
    }

    #[test]
    fn plain_http_can_differ_per_side() {
        // The case the single --plain-http switch cannot express: pull an
        // upstream image over HTTPS, push it into a local HTTP registry.
        let request = request_with(&["--target-plain-http"]);
        assert!(!request.source_plain_http);
        assert!(request.target_plain_http);

        let request = request_with(&["--source-plain-http"]);
        assert!(request.source_plain_http);
        assert!(!request.target_plain_http);
    }
}
