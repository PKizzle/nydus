// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
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
    /// A JSON access-pattern document, passed through to `nydus-image optimize`
    /// verbatim so its per-file byte ranges survive.
    PatternFile(PathBuf),
}

/// The access-pattern document `nydus-image optimize --prefetch-files` consumes.
///
/// Parsed only to validate it. The file is handed to the builder byte-for-byte rather than
/// re-serialised from this type, so a field nydusify does not model yet cannot be silently
/// dropped on the way through.
#[derive(Deserialize)]
struct AccessPatternDoc {
    #[serde(default)]
    version: Option<String>,
    files: Vec<AccessPatternFile>,
}

#[derive(Deserialize)]
struct AccessPatternFile {
    path: String,
}

/// Reject an access-pattern file that would produce a useless or confusing optimize run.
///
/// Worth doing here rather than leaving it to `nydus-image`: a prefetch failure is
/// deliberately non-fatal during conversion (the image is still published, just un-optimised),
/// so a typo in this file would otherwise cost a full convert-and-push to discover, and only
/// as a warning buried in the log.
fn validate_prefetch_pattern_file(path: &Path) -> Result<()> {
    let raw = std::fs::read(path)
        .with_context(|| format!("read --prefetch-pattern-file {}", path.display()))?;
    let doc: AccessPatternDoc = serde_json::from_slice(&raw).with_context(|| {
        format!(
            "parse --prefetch-pattern-file {} (expected {{\"version\":\"v1\",\"files\":[…]}})",
            path.display()
        )
    })?;
    if let Some(version) = doc.version.as_deref()
        && version != "v1"
    {
        bail!(
            "--prefetch-pattern-file {} declares version {:?}; only \"v1\" is understood",
            path.display(),
            version
        );
    }
    if doc.files.is_empty() {
        bail!(
            "--prefetch-pattern-file {} lists no files; omit the flag instead of \
             asking for an empty prefetch",
            path.display()
        );
    }
    if let Some(bad) = doc.files.iter().find(|f| !f.path.starts_with('/')) {
        bail!(
            "--prefetch-pattern-file {} contains {:?}; paths must be absolute inside the image",
            path.display(),
            bad.path
        );
    }
    Ok(())
}

pub async fn run(args: ConvertArgs) -> Result<()> {
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
    ContainerdConverter.convert(request).await
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
    if let Some(path) = &args.prefetch_pattern_file {
        if args.prefetch_dir.is_some() {
            bail!("--prefetch-pattern-file conflicts with --prefetch-dir");
        }
        if args.prefetch_patterns {
            bail!("--prefetch-pattern-file conflicts with --prefetch-patterns");
        }
        validate_existing_file(path, "--prefetch-pattern-file")?;
        validate_prefetch_pattern_file(path)?;
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

    let prefetch = if let Some(path) = &args.prefetch_pattern_file {
        PrefetchInput::PatternFile(path.clone())
    } else if args.prefetch_patterns {
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
        // The document travels as a path, not as patterns: flattening it to a list of
        // paths here would discard the per-file ranges that are the reason to use it.
        PrefetchInput::PatternFile(_) => Ok(String::new()),
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
        assert!(
            err.to_string()
                .contains("--build-cache conflicts with --build-cache-tag")
        );
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
        assert!(
            err.to_string()
                .contains("--build-cache-max-records should be greater than 0")
        );
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
        assert!(
            err.to_string()
                .contains("--all-platforms conflicts with --platform")
        );
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

    fn pattern_file(body: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn a_pattern_file_is_accepted_and_selected_over_the_other_prefetch_inputs() {
        let f = pattern_file(
            r#"{"version":"v1","files":[{"path":"/usr/bin/app","ranges":[[0,4096]]}]}"#,
        );
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "localhost:5000/app:v1",
            "--target",
            "localhost:5000/app:v1-nydus",
            "--prefetch-pattern-file",
            f.path().to_str().unwrap(),
        ]);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert")
        };
        let plan = plan(&args).unwrap();
        assert_eq!(plan.prefetch, PrefetchInput::PatternFile(f.path().into()));
        // The document travels by path; flattening it to patterns would drop the ranges.
        assert_eq!(read_prefetch_patterns(&plan).unwrap(), "");
    }

    #[test]
    fn a_pattern_file_conflicts_with_the_other_prefetch_inputs() {
        let f = pattern_file(r#"{"version":"v1","files":[{"path":"/a"}]}"#);
        for (flag, value) in [
            ("--prefetch-dir", Some("/usr")),
            ("--prefetch-patterns", None),
        ] {
            let mut argv = vec![
                "nydusify",
                "convert",
                "--source",
                "localhost:5000/app:v1",
                "--target",
                "localhost:5000/app:v1-nydus",
                "--prefetch-pattern-file",
                f.path().to_str().unwrap(),
                flag,
            ];
            if let Some(v) = value {
                argv.push(v);
            }
            let cli = Cli::parse_from(argv);
            let Commands::Convert(args) = cli.command else {
                panic!("expected convert")
            };
            let err = plan(&args).unwrap_err().to_string();
            assert!(err.contains(flag), "{flag}: unexpected error {err}");
        }
    }

    #[test]
    fn a_malformed_pattern_file_is_rejected_before_any_conversion_work() {
        // Each of these is silently useless if it reaches `nydus-image`, because a failed
        // optimize only warns and publishes an un-optimised image.
        let cases = [
            (r#"not json at all"#, "parse"),
            (r#"{"version":"v2","files":[{"path":"/a"}]}"#, "v1"),
            (r#"{"version":"v1","files":[]}"#, "no files"),
            (
                r#"{"version":"v1","files":[{"path":"usr/bin/app"}]}"#,
                "absolute",
            ),
        ];
        for (body, expected) in cases {
            let f = pattern_file(body);
            let err = validate_prefetch_pattern_file(f.path())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(expected),
                "body {body:?} should have complained about {expected:?}, said: {err}"
            );
        }
    }

    #[test]
    fn a_pattern_file_without_a_version_field_is_accepted() {
        // The field is optional in the document `nydus-image` consumes; only a *wrong*
        // version is an error.
        let f = pattern_file(r#"{"files":[{"path":"/a"}]}"#);
        validate_prefetch_pattern_file(f.path()).unwrap();
    }
}
