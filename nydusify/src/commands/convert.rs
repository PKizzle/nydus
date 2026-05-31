// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::io::{self, Read};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use tracing::info;

use crate::cli::ConvertArgs;
use crate::engine::containerd_converter::{ContainerdConverter, ConvertRequest, ImageConverter};

use super::common::{
    add_reference_suffix, parse_chunk_dict_reference, resolve_backend_config,
    validate_existing_file, validate_output_parent_dir, validate_platform_selection,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConvertPlan {
    pub source: String,
    pub target: String,
    pub mode: ConversionMode,
    pub oci_ref: bool,
    pub effective_oci: bool,
    pub fs_version: String,
    pub prefetch: PrefetchInput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ConversionMode {
    Forward,
    Reverse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum PrefetchInput {
    Root,
    Directory(String),
    StdinPatterns,
}

pub fn run(args: ConvertArgs) -> Result<()> {
    let plan = plan(&args)?;
    let prefetch_patterns = read_prefetch_patterns(&plan)?;
    let request = ConvertRequest::from_convert_args(&args, &plan, prefetch_patterns)?;
    info!(
        source = %plan.source,
        target = %plan.target,
        mode = ?plan.mode,
        oci_ref = plan.oci_ref,
        effective_oci = plan.effective_oci,
        "validated nydusify-rs convert request"
    );
    ContainerdConverter.convert(request)
}

pub fn plan(args: &ConvertArgs) -> Result<ConvertPlan> {
    if args.target.is_some() && args.target_suffix.is_some() {
        bail!("--target conflicts with --target-suffix");
    }
    let target = match (&args.target, &args.target_suffix) {
        (Some(target), None) => target.clone(),
        (None, Some(suffix)) => add_reference_suffix(&args.source, suffix)?,
        (None, None) => bail!("--target or --target-suffix is required"),
        (Some(_), Some(_)) => unreachable!(),
    };

    if args.build_cache.is_some() && args.build_cache_tag.is_some() {
        bail!("--build-cache conflicts with --build-cache-tag");
    }
    if args.build_cache_max_records == 0 {
        bail!("--build-cache-max-records should be greater than 0");
    }
    if args.prefetch_dir.is_some() && args.prefetch_patterns {
        bail!("--prefetch-dir conflicts with --prefetch-patterns");
    }
    if let Some(path) = &args.source_archive {
        validate_existing_file(path, "--source-archive")?;
    }
    if let Some(path) = &args.target_archive {
        validate_output_parent_dir(path, "--target-archive")?;
    }
    if !matches!(args.fs_version.as_str(), "5" | "6") {
        bail!("--fs-version should be one of [5, 6]");
    }
    validate_platform_selection(args.all_platforms, args.platform.as_deref())?;
    let _ = resolve_backend_config(
        args.backend_type,
        args.backend_config.as_deref(),
        args.backend_config_file.as_deref(),
        "",
    )?;
    let _ = resolve_backend_config(
        args.source_backend_type,
        args.source_backend_config.as_deref(),
        args.source_backend_config_file.as_deref(),
        "source-",
    )?;
    if let Some(chunk_dict) = &args.chunk_dict {
        let _ = parse_chunk_dict_reference(chunk_dict)?;
    }

    let prefetch = if args.prefetch_patterns {
        PrefetchInput::StdinPatterns
    } else if let Some(path) = &args.prefetch_dir {
        PrefetchInput::Directory(path.clone())
    } else {
        PrefetchInput::Root
    };

    Ok(ConvertPlan {
        source: args.source.clone(),
        target,
        mode: if args.reverse {
            ConversionMode::Reverse
        } else {
            ConversionMode::Forward
        },
        oci_ref: args.oci_ref,
        effective_oci: args.oci || args.oci_ref,
        fs_version: args.fs_version.clone(),
        prefetch,
    })
}

fn read_prefetch_patterns(plan: &ConvertPlan) -> Result<String> {
    match &plan.prefetch {
        PrefetchInput::Root => Ok("/".to_string()),
        PrefetchInput::Directory(path) => Ok(path.clone()),
        PrefetchInput::StdinPatterns => {
            let mut patterns = String::new();
            io::stdin()
                .read_to_string(&mut patterns)
                .context("read prefetch patterns from stdin")?;
            Ok(patterns)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::Parser;

    #[test]
    fn oci_ref_implies_oci_media_types() {
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target-suffix",
            "-nydus-oci-ref",
            "--oci-ref",
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };

        let plan = plan(&args).unwrap();
        assert!(plan.oci_ref);
        assert!(plan.effective_oci);
        assert_eq!(plan.mode, ConversionMode::Forward);
        assert_eq!(plan.target, "registry.local/app:latest-nydus-oci-ref");
    }

    #[test]
    fn rejects_prefetch_conflict() {
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target",
            "registry.local/app:nydus",
            "--prefetch-dir",
            "/usr/bin",
            "--prefetch-patterns",
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };

        let err = plan(&args).unwrap_err();
        assert!(err.to_string().contains("--prefetch-dir conflicts"));
    }

    #[test]
    fn rejects_build_cache_with_build_cache_tag() {
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target",
            "registry.local/app:nydus",
            "--build-cache",
            "registry.local/app:cache",
            "--build-cache-tag",
            "registry.local/app:latest-cache",
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };

        let err = plan(&args).unwrap_err();
        assert!(err
            .to_string()
            .contains("--build-cache conflicts with --build-cache-tag"));
    }

    #[test]
    fn rejects_zero_build_cache_max_records() {
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target",
            "registry.local/app:nydus",
            "--build-cache-max-records",
            "0",
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };

        let err = plan(&args).unwrap_err();
        assert!(err
            .to_string()
            .contains("--build-cache-max-records should be greater than 0"));
    }

    #[test]
    fn rejects_invalid_fs_version() {
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target",
            "registry.local/app:nydus",
            "--fs-version",
            "7",
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };

        let err = plan(&args).unwrap_err();
        assert!(err.to_string().contains("--fs-version should be one of"));
    }

    #[test]
    fn rejects_all_platforms_with_explicit_platform() {
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target",
            "registry.local/app:nydus",
            "--all-platforms",
            "--platform",
            "linux/amd64",
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };

        let err = plan(&args).unwrap_err();
        assert!(err
            .to_string()
            .contains("--all-platforms conflicts with --platform"));
    }

    #[test]
    fn rejects_missing_source_archive() {
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target",
            "registry.local/app:nydus",
            "--source-archive",
            "/definitely/missing/archive.tar",
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };

        let err = plan(&args).unwrap_err();
        assert!(err.to_string().contains("--source-archive"));
    }
}
