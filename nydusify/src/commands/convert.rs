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
    /// The image reference the conversion is anchored to: the uppermost `--source`
    /// that is an image. It supplies the runtime config, the platform, and the repo
    /// that reused blobs are mounted from.
    pub source: String,
    /// Every source in stacking order, lowest first. A single-entry list is the
    /// ordinary one-image conversion.
    pub sources: Vec<SourceSpec>,
    pub target: String,
    pub mode: ConversionMode,
    pub oci_ref: bool,
    pub effective_oci: bool,
    pub fs_version: String,
    pub prefetch: PrefetchInput,
}

/// One `--source` value, classified.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceSpec {
    /// An image reference, pulled and converted layer by layer.
    Image(String),
    /// A local directory, built into a single nydus layer with
    /// `nydus-image create --type dir-rafs`.
    Directory(PathBuf),
}

/// Does this `--source` value name a filesystem path rather than an image reference?
///
/// An OCI reference can never begin with `/`, `./` or `../`: its first component is a registry
/// host or a repository name, and neither may start with a dot or a slash. So these prefixes
/// are an unambiguous statement of intent, and a value carrying one is held to it instead of
/// being handed to the registry parser -- where `./rootfs.tar` would otherwise resolve to a
/// registry host literally named `.`.
fn looks_like_a_path(value: &str) -> bool {
    value.starts_with('/') || value.starts_with("./") || value.starts_with("../")
}

/// Decide whether a `--source` value names a local directory or an image.
///
/// Existence on disk is the test for anything that does not already look like a path, and it is
/// deliberately one-way: an image reference that happens to collide with a directory in the
/// working directory is misread, but the reverse -- a directory silently treated as a registry
/// reference -- fails much later and far more confusingly.
///
/// Directories are canonicalised, which matters for more than tidiness: `nydus-image` builds its
/// root node with `symlink_metadata`, so handing it a symlink to a directory yields a root that
/// is not a directory and therefore an empty layer, with no diagnostic at all.
fn classify_source(value: &str) -> Result<SourceSpec> {
    let path = Path::new(value);
    if path.is_dir() {
        let canonical = path
            .canonicalize()
            .with_context(|| format!("resolve --source directory {value}"))?;
        return Ok(SourceSpec::Directory(canonical));
    }
    if looks_like_a_path(value) {
        let what = if path.symlink_metadata().is_ok() {
            "is not a directory"
        } else {
            "does not exist"
        };
        bail!(
            "--source {value} {what}; a path-like source must be a directory, and an image \
             reference cannot begin with {:?}",
            value.split('/').next().unwrap_or(value)
        );
    }
    Ok(SourceSpec::Image(value.to_string()))
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
    version: String,
    files: Vec<AccessPatternFile>,
}

#[derive(Deserialize)]
struct AccessPatternFile {
    path: String,
    /// `[[offset, size], ...]`, the reason this flag exists over `--prefetch-dir`.
    ///
    /// Modelled only so a malformed shape is caught here; the builder reads the ranges out of
    /// the file itself, not out of this type.
    #[serde(default)]
    #[allow(dead_code)]
    ranges: Option<Vec<[u64; 2]>>,
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
    if doc.version != "v1" {
        bail!(
            "--prefetch-pattern-file {} declares version {:?}; only \"v1\" is understood",
            path.display(),
            doc.version
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
    let sources: Vec<SourceSpec> = args
        .source
        .iter()
        .map(|s| classify_source(s))
        .collect::<Result<_>>()?;
    if sources.is_empty() {
        bail!("--source is required");
    }
    // The uppermost image source anchors the conversion. Without one there is no config
    // to inherit, no platform to resolve against and no repo to mount reused blobs from,
    // all of which the pipeline below assumes exist.
    let anchor = sources
        .iter()
        .rev()
        .find_map(|s| match s {
            SourceSpec::Image(reference) => Some(reference.clone()),
            SourceSpec::Directory(_) => None,
        })
        .with_context(|| {
            "every --source is a local directory; at least one must be an image reference, \
             whose config (env, entrypoint, architecture) the converted image inherits"
        })?;

    if sources.len() > 1 {
        // Each of these is incompatible with stacking for a concrete reason, and saying
        // so up front beats a confusing failure several minutes into a conversion.
        if args.oci_ref {
            bail!(
                "--oci-ref cannot be combined with multiple --source values: zran records \
                 offsets into each layer's original gzip stream, and a directory source has \
                 no such stream"
            );
        }
        if args.source_archive.is_some() {
            bail!(
                "--source-archive reads a single image; it cannot be combined with multiple --source values"
            );
        }
        if args.all_platforms {
            bail!(
                "--all-platforms cannot be combined with multiple --source values: the sources \
                 are stacked into one image, so exactly one platform is converted (use --platform)"
            );
        }
        // Same reason as --all-platforms, which would otherwise be the only way in: a comma
        // list is expanded into one conversion per platform, and a directory source has no
        // per-architecture variant to offer them -- the same bytes would be stacked into every
        // architecture's image and labelled as native to it.
        if let Some(platform) = args.platform.as_deref()
            && platform.contains(',')
        {
            bail!(
                "--platform {platform} names more than one platform, which cannot be combined \
                 with multiple --source values: the sources are stacked into one image, so \
                 exactly one platform is converted"
            );
        }
        if args.with_referrer {
            bail!(
                "--with-referrer cannot be combined with multiple --source values: the referrer \
                 artifact is attached to the uppermost image source, which would advertise the \
                 stacked image as a plain nydus conversion of that one image"
            );
        }
    }

    if args.target.is_some() && args.target_suffix.is_some() {
        bail!("--target conflicts with --target-suffix");
    }
    let target = match (&args.target, &args.target_suffix) {
        (Some(target), None) => target.clone(),
        (None, Some(suffix)) => add_reference_suffix(&anchor, suffix)?,
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
        source: anchor,
        sources,
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
            // `ranges` is the whole reason this flag exists over `--prefetch-dir`, so a
            // malformed one must not sail through to a warning buried in the build log.
            (
                r#"{"version":"v1","files":[{"path":"/a","ranges":"everything"}]}"#,
                "parse",
            ),
            (
                r#"{"version":"v1","files":[{"path":"/a","ranges":[[0,1,2]]}]}"#,
                "parse",
            ),
            (
                r#"{"version":"v1","files":[{"path":"/a","ranges":[[-1,5]]}]}"#,
                "parse",
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

    /// Build a convert CLI over `sources`, in order.
    fn convert_args(sources: &[&str], extra: &[&str]) -> ConvertArgs {
        let mut argv = vec!["nydusify".to_string(), "convert".to_string()];
        for s in sources {
            argv.push("--source".to_string());
            argv.push((*s).to_string());
        }
        argv.push("--target".to_string());
        argv.push("localhost:5000/app:v1-nydus".to_string());
        argv.extend(extra.iter().map(|s| (*s).to_string()));
        let cli = Cli::parse_from(argv);
        let Commands::Convert(args) = cli.command else {
            panic!("expected convert")
        };
        *args
    }

    #[test]
    fn a_single_image_source_plans_exactly_as_before() {
        let plan = plan(&convert_args(&["localhost:5000/app:v1"], &[])).unwrap();
        assert_eq!(plan.source, "localhost:5000/app:v1");
        assert_eq!(
            plan.sources,
            vec![SourceSpec::Image("localhost:5000/app:v1".into())]
        );
    }

    #[test]
    fn sources_keep_their_order_and_the_uppermost_image_anchors() {
        let lower = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        let plan = plan(&convert_args(
            &[
                lower.path().to_str().unwrap(),
                "localhost:5000/base:v1",
                "localhost:5000/app:v2",
                upper.path().to_str().unwrap(),
            ],
            &[],
        ))
        .unwrap();

        // Stacking order is preserved verbatim: it is the merge order. Directories come back
        // canonicalised, so compare against the resolved paths.
        assert_eq!(
            plan.sources,
            vec![
                SourceSpec::Directory(lower.path().canonicalize().unwrap()),
                SourceSpec::Image("localhost:5000/base:v1".into()),
                SourceSpec::Image("localhost:5000/app:v2".into()),
                SourceSpec::Directory(upper.path().canonicalize().unwrap()),
            ]
        );
        // ...but the anchor is the uppermost *image*, even with a directory above it.
        assert_eq!(plan.source, "localhost:5000/app:v2");
    }

    #[test]
    fn a_directory_only_conversion_is_refused_with_the_reason() {
        let d = tempfile::tempdir().unwrap();
        let err = plan(&convert_args(&[d.path().to_str().unwrap()], &[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least one must be an image"), "got: {err}");
    }

    #[test]
    fn a_path_like_source_that_is_not_a_directory_is_refused() {
        // `./x` cannot be an image reference -- the registry parser would read the leading
        // "." as a hostname -- so each of these is caught here rather than in a pull.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("rootfs.tar");
        std::fs::write(&file, b"x").unwrap();
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();

        for (value, needle) in [
            (file.to_str().unwrap(), "is not a directory"),
            (dangling.to_str().unwrap(), "is not a directory"),
            ("./no/such/dir", "does not exist"),
        ] {
            let err = plan(&convert_args(&[value], &[])).unwrap_err().to_string();
            assert!(err.contains(needle), "{value} should say {needle}: {err}");
        }

        // A bare name is still an image reference, even though nothing of that name exists.
        let plan = plan(&convert_args(&["localhost:5000/app:v1"], &[])).unwrap();
        assert_eq!(
            plan.sources,
            vec![SourceSpec::Image("localhost:5000/app:v1".into())]
        );
    }

    #[test]
    fn a_symlinked_directory_source_is_resolved_to_its_target() {
        // `nydus-image` stats the root with symlink_metadata, so a symlink root is not a
        // directory to it and the layer comes out empty with no diagnostic.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let plan = plan(&convert_args(
            &["localhost:5000/app:v1", link.to_str().unwrap()],
            &[],
        ))
        .unwrap();
        assert_eq!(
            plan.sources[1],
            SourceSpec::Directory(real.canonicalize().unwrap())
        );
    }

    #[test]
    fn stacking_is_refused_for_the_options_it_cannot_honour() {
        let d = tempfile::tempdir().unwrap();
        let sources = ["localhost:5000/app:v1", d.path().to_str().unwrap()];
        for (flags, needle) in [
            (vec!["--oci-ref"], "zran"),
            (vec!["--all-platforms"], "one platform"),
            (vec!["--source-archive", "/nonexistent.tar"], "single image"),
            (
                vec!["--platform", "linux/amd64,linux/arm64"],
                "more than one platform",
            ),
            (vec!["--with-referrer"], "uppermost image source"),
        ] {
            let err = plan(&convert_args(&sources, &flags))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(needle),
                "{flags:?} should mention {needle}: {err}"
            );
        }
        // ...and none of them is refused for an ordinary single-source convert.
        for flags in [
            vec!["--oci-ref"],
            vec!["--platform", "linux/amd64,linux/arm64"],
            vec!["--with-referrer"],
        ] {
            plan(&convert_args(&["localhost:5000/app:v1"], &flags)).unwrap();
        }
    }

    #[test]
    fn a_pattern_file_without_a_version_field_is_rejected() {
        // `PrefetchJson` in builder/src/optimize_prefetch.rs declares `version: String`, so a
        // version-less document dies inside `nydus-image` -- and a failed optimize only warns,
        // which is precisely the silent failure this validation exists to prevent.
        let f = pattern_file(r#"{"files":[{"path":"/a"}]}"#);
        let err = validate_prefetch_pattern_file(f.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("version"), "got: {err}");
    }

    #[test]
    fn a_pattern_file_with_ranges_round_trips_the_shapes_the_builder_accepts() {
        let f = pattern_file(
            r#"{"version":"v1","files":[
                 {"path":"/usr/bin/app","ranges":[[0,4096],[8192,512]]},
                 {"path":"/etc/conf"}
               ]}"#,
        );
        validate_prefetch_pattern_file(f.path()).unwrap();
    }
}
