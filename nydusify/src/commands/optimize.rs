// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! `nydusify optimize` — rebuild an existing nydus image's prefetch layout.
//!
//! The image is already published, so its data blobs are left exactly where they are: the
//! optimize run reads the ranges it needs straight out of the source registry (`nydus-image
//! optimize --backend-type registry`) instead of downloading every blob to disk. What comes out
//! is one additional data blob holding the prefetched bytes, plus a rewritten bootstrap that
//! points the prefetch table at it. The pushed image reuses every original data layer and
//! appends the new one.
//!
//! `convert` runs the same builder step as a best-effort extra — a conversion still has a usable
//! image to publish if optimize fails, so it warns and pushes the un-optimized bootstrap. This
//! command has nothing else to deliver, so any failure is fatal and nothing is pushed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use registry_client::types::{Manifest, sha256_digest};
use registry_client::{Descriptor, ImageReference, RegistryClient};
use serde::Serialize;
use serde_json::json;
use tracing::{info, warn};

use crate::cli::OptimizeArgs;
use crate::commands::convert::validate_prefetch_pattern_file;
use crate::engine::bootstrap_layer;
use crate::engine::manifest::{
    ANNOTATION_NYDUS_BOOTSTRAP, assemble_manifest, bootstrap_descriptor, config_media_type,
    data_blob_descriptor, manifest_media_type, rebuild_image_config, validate_nydus_manifest,
};
use crate::engine::oci::{client_options, fetch_nydus_platform_manifest};
use crate::engine::retry::RetryPolicy;

use super::common::{resolve_platform, validate_existing_file};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OptimizePlan {
    pub source: String,
    pub target: String,
    pub platform: String,
    pub prefetch_pattern_file: PathBuf,
}

pub fn plan(args: &OptimizeArgs) -> Result<OptimizePlan> {
    if args.source.trim().is_empty() {
        bail!("--source is required");
    }
    if args.target.trim().is_empty() {
        bail!("--target is required");
    }
    validate_existing_file(&args.prefetch_pattern_file, "--prefetch-pattern-file")?;
    validate_prefetch_pattern_file(&args.prefetch_pattern_file)?;

    Ok(OptimizePlan {
        source: args.source.clone(),
        target: args.target.clone(),
        platform: resolve_platform(args.platform.as_deref()),
        prefetch_pattern_file: args.prefetch_pattern_file.clone(),
    })
}

pub async fn run(args: OptimizeArgs) -> Result<()> {
    let plan = plan(&args)?;
    info!(
        source = %plan.source,
        target = %plan.target,
        platform = %plan.platform,
        "validated nydusify-rs optimize request"
    );

    let source_ref = ImageReference::parse(&plan.source)
        .with_context(|| format!("parse --source {}", plan.source))?;
    let target_ref = ImageReference::parse(&plan.target)
        .with_context(|| format!("parse --target {}", plan.target))?;
    let source_plain_http = args.plain_http || args.source_plain_http;
    let target_plain_http = args.plain_http || args.target_plain_http;

    let source_client = RegistryClient::new(
        &source_ref.api_host,
        client_options(args.source_insecure, source_plain_http, &args.ca_cert),
    )
    .context("build source registry client")?;
    let target_client = RegistryClient::new(
        &target_ref.api_host,
        client_options(args.target_insecure, target_plain_http, &args.ca_cert),
    )
    .context("build target registry client")?;
    let same_registry = source_ref.api_host == target_ref.api_host;
    let retry = RetryPolicy::from_flags(args.push_retry_count, &args.push_retry_delay);

    let workspace = tempfile::Builder::new()
        .prefix("nydusify-optimize-")
        .tempdir_in(ensure_work_dir(&args.work_dir)?)
        .context("create optimize workspace")?;
    let work = workspace.path();

    // ---- resolve the source image ----
    let fetched = fetch_nydus_platform_manifest(
        &source_client,
        &source_ref.repo,
        source_ref.manifest_reference(),
        &plan.platform,
    )
    .await?;
    let manifest: Manifest =
        serde_json::from_slice(&fetched.bytes).context("parse source manifest")?;
    let bootstrap_desc = validate_nydus_manifest(&manifest)
        .with_context(|| format!("--source {source_ref} is not a nydus image"))?
        .clone();

    let config_bytes = source_client
        .get_blob(&source_ref.repo, &manifest.config.digest)
        .await
        .context("fetch source image config")?;

    let bootstrap = bootstrap_layer::fetch(&source_client, &source_ref.repo, &bootstrap_desc, work)
        .await
        .context("fetch the source bootstrap")?;

    // ---- optimize (reads blob ranges from the source registry on demand) ----
    let prefetch_blob = run_optimize(
        &args.nydus_image,
        work,
        &bootstrap,
        &plan.prefetch_pattern_file,
        &source_ref,
        args.source_insecure,
        source_plain_http,
    )?;

    // ---- push ----
    // Every original data layer is reused as-is; only the prefetch blob is new.
    let original_data_layers: Vec<&Descriptor> = manifest
        .layers
        .iter()
        .filter(|l| !is_bootstrap_layer(l))
        .collect();
    if original_data_layers.is_empty() {
        bail!("source manifest has no data layers to reuse");
    }

    let staging = work.join("staging");
    std::fs::create_dir_all(&staging).with_context(|| format!("create {}", staging.display()))?;
    let mut data_blobs = Vec::with_capacity(original_data_layers.len() + 1);
    for layer in &original_data_layers {
        copy_blob(
            &source_client,
            &source_ref.repo,
            &target_client,
            &target_ref.repo,
            same_registry,
            &layer.digest,
            &staging,
            &retry,
        )
        .await?;
        // Reuse the descriptor verbatim: its media type and annotations (including the
        // uncompressed diff id) are what the snapshotter classifies the layer by.
        data_blobs.push((*layer).clone());
    }

    let prefetch_digest = retry
        .run("push prefetch blob", || {
            target_client.push_blob_file(&target_ref.repo, &prefetch_blob)
        })
        .await
        .context("push the optimize prefetch blob")?;
    let prefetch_size = std::fs::metadata(&prefetch_blob)
        .with_context(|| format!("stat {}", prefetch_blob.display()))?
        .len();
    data_blobs.push(data_blob_descriptor(prefetch_digest, prefetch_size));

    let docker2oci = manifest
        .media_type
        .as_deref()
        .is_some_and(|m| m.contains("oci"));
    let boot_layer = bootstrap_layer::pack(&bootstrap, &[])?;
    let boot_digest = retry
        .run("push optimized bootstrap", || {
            target_client.push_blob_bytes(&target_ref.repo, &boot_layer.gzip_bytes)
        })
        .await
        .context("push the optimized bootstrap")?;
    let bootstrap_layer_desc = bootstrap_descriptor(
        boot_digest,
        boot_layer.diff_id.clone(),
        boot_layer.gzip_bytes.len() as u64,
    );

    let layer_digests: Vec<String> = data_blobs
        .iter()
        .map(diff_id_of)
        .chain(std::iter::once(boot_layer.diff_id.clone()))
        .collect();
    let new_config = rebuild_image_config(&config_bytes, &layer_digests)
        .context("rewrite the image config for the optimized layer set")?;
    let config_digest = retry
        .run("push image config", || {
            target_client.push_blob_bytes(&target_ref.repo, &new_config)
        })
        .await
        .context("push the rewritten image config")?;
    let config_desc = Descriptor {
        media_type: config_media_type(docker2oci).to_string(),
        digest: config_digest,
        size: new_config.len() as u64,
        ..Descriptor::default()
    };

    let new_manifest = assemble_manifest(docker2oci, config_desc, data_blobs, bootstrap_layer_desc);
    let manifest_bytes =
        serde_json::to_vec(&new_manifest).context("serialize the optimized manifest")?;
    retry
        .run("push manifest", || {
            target_client.push_manifest(
                &target_ref.repo,
                target_ref.manifest_reference(),
                manifest_media_type(docker2oci),
                &manifest_bytes,
            )
        })
        .await
        .context("push the optimized manifest")?;

    info!(
        target = %target_ref,
        manifest = %sha256_digest(&manifest_bytes),
        data_blobs = new_manifest.layers.len() - 1,
        "optimize complete: pushed optimized nydus image"
    );
    Ok(())
}

/// The diff id a layer descriptor advertises, falling back to its own digest.
///
/// A nydus data blob is uncompressed at the layer level, so the two are the same for blobs this
/// tool builds; the annotation is still preferred because a blob from another builder may carry
/// a diff id that is not its content digest.
fn diff_id_of(desc: &Descriptor) -> String {
    desc.annotations
        .as_ref()
        .and_then(|a| a.get(crate::engine::manifest::ANNOTATION_UNCOMPRESSED))
        .cloned()
        .unwrap_or_else(|| desc.digest.clone())
}

fn is_bootstrap_layer(layer: &Descriptor) -> bool {
    layer
        .annotations
        .as_ref()
        .and_then(|a| a.get(ANNOTATION_NYDUS_BOOTSTRAP))
        .is_some_and(|v| v == "true")
        || layer.media_type.contains("bootstrap.nydus")
}

/// Run `nydus-image optimize` against the source registry.
///
/// The blobs stay in the registry: `--backend-type registry` lets the builder range-read exactly
/// the chunks the pattern names, which is the whole point of optimizing a published image rather
/// than re-converting it.
fn run_optimize(
    nydus_image: &Path,
    work: &Path,
    bootstrap: &Path,
    pattern_file: &Path,
    source_ref: &ImageReference,
    skip_verify: bool,
    plain_http: bool,
) -> Result<PathBuf> {
    // Credentials for the source registry, so the builder's own blob reads authenticate.
    let auth = registry_client::auth::docker_config_auth(None, &source_ref.api_host);
    if auth.is_none() {
        warn!(
            registry = %source_ref.api_host,
            "no docker-config credentials found; nydus-image will read source blobs anonymously"
        );
    }
    let mut backend_config = json!({
        // An empty scheme lets the builder auto-detect, which in practice means HTTPS -- so a
        // plain-HTTP registry has to be named explicitly or every blob read fails the TLS
        // handshake with an "invalid content type" that says nothing about the cause.
        "scheme": if plain_http { "http" } else { "" },
        "host": source_ref.api_host,
        "repo": source_ref.repo,
        "skip_verify": skip_verify,
    });
    if let Some(auth) = &auth {
        backend_config["auth"] = json!(auth);
    }
    let backend_config_path = work.join("backend.json");
    std::fs::write(
        &backend_config_path,
        serde_json::to_vec(&backend_config).context("serialize the registry backend config")?,
    )
    .with_context(|| format!("write {}", backend_config_path.display()))?;

    let out_blob_dir = work.join("optimize-out");
    std::fs::create_dir_all(&out_blob_dir)
        .with_context(|| format!("create {}", out_blob_dir.display()))?;
    let optimized = work.join("bootstrap.optimized");

    let args: Vec<OsString> = vec![
        "optimize".into(),
        "--bootstrap".into(),
        bootstrap.into(),
        "--prefetch-files".into(),
        pattern_file.into(),
        "--backend-type".into(),
        "registry".into(),
        "--backend-config-file".into(),
        backend_config_path.as_path().into(),
        "--output-bootstrap".into(),
        optimized.as_path().into(),
        "--output-blob-dir".into(),
        out_blob_dir.as_path().into(),
    ];
    let output = std::process::Command::new(nydus_image)
        .args(&args)
        .output()
        .with_context(|| format!("spawn `{}` for optimize", nydus_image.display()))?;
    if !output.status.success() {
        bail!(
            "nydus-image optimize failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let prefetch_blob = single_file(&out_blob_dir)?.with_context(|| {
        format!(
            "nydus-image optimize produced no prefetch blob in {}; the pattern may name no file \
             present in the image",
            out_blob_dir.display()
        )
    })?;
    // Swap only after the prefetch blob is known to exist: the optimized bootstrap references
    // it, so publishing one without the other would serve a prefetch table pointing at nothing.
    std::fs::rename(&optimized, bootstrap)
        .context("replace the bootstrap with the optimized one")?;
    Ok(prefetch_blob)
}

/// The single regular file in `dir`, or `None` when it is empty.
fn single_file(dir: &Path) -> Result<Option<PathBuf>> {
    let mut found = None;
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if found.is_some() {
            bail!(
                "expected exactly one output file in {}, found more than one",
                dir.display()
            );
        }
        found = Some(entry.path());
    }
    Ok(found)
}

/// Move one blob from the source repo to the target repo: skip when the target already has it,
/// cross-repo mount within one registry, else download and re-push.
#[allow(clippy::too_many_arguments)]
async fn copy_blob(
    source_client: &RegistryClient,
    source_repo: &str,
    target_client: &RegistryClient,
    target_repo: &str,
    same_registry: bool,
    digest: &str,
    staging: &Path,
    retry: &RetryPolicy,
) -> Result<()> {
    crate::engine::oci::ensure_blob_in_repo(
        target_client,
        target_repo,
        Some(source_repo),
        same_registry,
        digest,
        crate::engine::oci::BlobSource::Download {
            client: source_client,
            staging,
        },
        retry,
    )
    .await
}

fn ensure_work_dir(dir: &Path) -> Result<&Path> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create work directory {}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::Parser;
    use std::collections::BTreeMap;
    use std::io::Write;

    fn pattern_file(body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn optimize_args(pattern: &Path, extra: &[&str]) -> OptimizeArgs {
        let mut argv = vec![
            "nydusify".to_string(),
            "optimize".to_string(),
            "--source".to_string(),
            "localhost:5000/app:v1-nydus".to_string(),
            "--target".to_string(),
            "localhost:5000/app:v1-opt".to_string(),
            "--prefetch-pattern-file".to_string(),
            pattern.display().to_string(),
        ];
        argv.extend(extra.iter().map(|s| (*s).to_string()));
        let cli = Cli::parse_from(argv);
        let Commands::Optimize(args) = cli.command else {
            panic!("expected optimize")
        };
        *args
    }

    #[test]
    fn a_valid_request_plans_with_the_host_platform_by_default() {
        let f = pattern_file(r#"{"version":"v1","files":[{"path":"/usr/bin/app"}]}"#);
        let plan = plan(&optimize_args(f.path(), &[])).unwrap();
        assert_eq!(plan.source, "localhost:5000/app:v1-nydus");
        assert_eq!(plan.target, "localhost:5000/app:v1-opt");
        assert_eq!(plan.platform, crate::cli::default_platform());
    }

    #[test]
    fn the_pattern_file_is_validated_the_same_way_convert_validates_it() {
        // Same schema, same errors -- a document that convert refuses must not be accepted
        // here, where the optimize run is the entire point of the command.
        for (body, needle) in [
            (r#"{"files":[{"path":"/a"}]}"#, "version"),
            (r#"{"version":"v1","files":[]}"#, "no files"),
            (r#"{"version":"v1","files":[{"path":"rel"}]}"#, "absolute"),
            (
                r#"{"version":"v1","files":[{"path":"/a","ranges":[[0,1,2]]}]}"#,
                "parse",
            ),
        ] {
            let f = pattern_file(body);
            let err = plan(&optimize_args(f.path(), &[])).unwrap_err().to_string();
            assert!(err.contains(needle), "{body} should say {needle}: {err}");
        }
    }

    #[test]
    fn a_missing_pattern_file_is_refused_before_anything_is_pulled() {
        let err = plan(&optimize_args(Path::new("/no/such/pattern.json"), &[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--prefetch-pattern-file"), "got: {err}");
    }

    #[test]
    fn the_bootstrap_layer_is_recognised_by_annotation_or_media_type() {
        let annotated = Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            annotations: Some(BTreeMap::from([(
                ANNOTATION_NYDUS_BOOTSTRAP.to_string(),
                "true".to_string(),
            )])),
            ..Descriptor::default()
        };
        assert!(is_bootstrap_layer(&annotated));

        let by_media_type = Descriptor {
            media_type: "application/vnd.oci.image.layer.bootstrap.nydus.v1".to_string(),
            ..Descriptor::default()
        };
        assert!(is_bootstrap_layer(&by_media_type));

        let data = Descriptor {
            media_type: "application/vnd.oci.image.layer.nydus.blob.v1".to_string(),
            ..Descriptor::default()
        };
        assert!(!is_bootstrap_layer(&data));
    }

    #[test]
    fn a_data_layers_diff_id_comes_from_its_annotation_when_it_has_one() {
        // A blob built elsewhere may advertise a diff id that is not its content digest;
        // taking the digest anyway would produce a config containerd rejects.
        let annotated = Descriptor {
            digest: "sha256:aa".to_string(),
            annotations: Some(BTreeMap::from([(
                crate::engine::manifest::ANNOTATION_UNCOMPRESSED.to_string(),
                "sha256:bb".to_string(),
            )])),
            ..Descriptor::default()
        };
        assert_eq!(diff_id_of(&annotated), "sha256:bb");

        let bare = Descriptor {
            digest: "sha256:cc".to_string(),
            ..Descriptor::default()
        };
        assert_eq!(diff_id_of(&bare), "sha256:cc");
    }

    #[test]
    fn single_file_reports_emptiness_rather_than_guessing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(single_file(dir.path()).unwrap().is_none());

        std::fs::write(dir.path().join("blob"), b"x").unwrap();
        assert_eq!(
            single_file(dir.path()).unwrap().unwrap(),
            dir.path().join("blob")
        );

        std::fs::write(dir.path().join("another"), b"y").unwrap();
        assert!(single_file(dir.path()).is_err());
    }
}
