// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use registry_client::types::{MEDIA_TYPE_OCI_MANIFEST, Manifest};
use registry_client::{ImageReference, Index, RegistryClient};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::cli::CopyArgs;
use crate::engine::oci::{blob_hex, client_options, is_index, select_platform};
use crate::engine::retry::RetryPolicy;

use super::common::{resolve_backend_config, resolve_platform, validate_platform_selection};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CopyPlan {
    pub source: String,
    pub target: Option<String>,
    pub platform: String,
    pub all_platforms: bool,
    pub push_chunk_size: String,
}

pub async fn run(args: CopyArgs) -> Result<()> {
    let plan = plan(&args)?;
    if plan.all_platforms {
        bail!(
            "--all-platforms is not yet supported by nydusify-rs; copy one platform at a time with --platform (follow-up)"
        );
    }
    if plan.push_chunk_size != "0MB" {
        bail!(
            "--push-chunk-size {} is not yet supported by nydusify-rs; chunked uploads are out of scope (follow-up)",
            plan.push_chunk_size
        );
    }
    let target = plan
        .target
        .clone()
        .ok_or_else(|| anyhow!("copy requires --target"))?;

    let source_ref = ImageReference::parse(&plan.source)
        .with_context(|| format!("parse --source {}", plan.source))?;
    let target_ref =
        ImageReference::parse(&target).with_context(|| format!("parse --target {target}"))?;

    let source_client = RegistryClient::new(
        &source_ref.api_host,
        client_options(args.source_insecure, false),
    )
    .context("build source registry client")?;
    let target_client = RegistryClient::new(
        &target_ref.api_host,
        client_options(args.target_insecure, false),
    )
    .context("build target registry client")?;
    let same_registry = source_ref.api_host == target_ref.api_host;

    info!(source = %source_ref, target = %target_ref, platform = %plan.platform, "copying image");

    let retry = RetryPolicy::default();

    // Fetch the top-level reference; if it is a multi-platform index, resolve to
    // a single platform manifest and warn loudly that the copied tag will NOT be
    // multi-arch (a real degradation of the source).
    let top = source_client
        .get_manifest(&source_ref.repo, source_ref.manifest_reference())
        .await
        .with_context(|| format!("fetch source manifest {source_ref}"))?;
    let fetched = if is_index(top.content_type.as_deref(), &top.bytes) {
        warn!(
            source = %source_ref,
            platform = %plan.platform,
            "source is a multi-platform index; copying only the {} manifest — the copied tag will be single-arch, not a full index",
            plan.platform
        );
        let index: Index =
            serde_json::from_slice(&top.bytes).context("parse source image index")?;
        let selected = select_platform(&index, &plan.platform)?;
        source_client
            .get_manifest(&source_ref.repo, &selected.digest)
            .await
            .with_context(|| format!("fetch platform manifest {}", selected.digest))?
    } else {
        top
    };
    let manifest: Manifest =
        serde_json::from_slice(&fetched.bytes).context("parse source image manifest")?;

    // Staging dir for blobs that must be downloaded then re-pushed.
    ensure_dir(&args.work_dir)?;
    let staging = tempfile::Builder::new()
        .prefix("nydusify-copy-")
        .tempdir_in(&args.work_dir)
        .with_context(|| format!("create staging dir in {}", args.work_dir.display()))?;

    // Copy the config blob and every layer.
    copy_blob(
        &source_client,
        &source_ref.repo,
        &target_client,
        &target_ref.repo,
        same_registry,
        &manifest.config.digest,
        staging.path(),
        &retry,
    )
    .await
    .with_context(|| format!("copy image config {}", manifest.config.digest))?;
    for layer in &manifest.layers {
        copy_blob(
            &source_client,
            &source_ref.repo,
            &target_client,
            &target_ref.repo,
            same_registry,
            &layer.digest,
            staging.path(),
            &retry,
        )
        .await
        .with_context(|| format!("copy layer {}", layer.digest))?;
    }

    // Push the manifest last (its blobs now all exist in the target repo). Use
    // the manifest's own embedded mediaType so a docker schema-2 manifest is not
    // silently re-typed as OCI; fall back to the response Content-Type, then to
    // OCI as a last resort.
    let media_type = manifest
        .media_type
        .as_deref()
        .or(fetched.content_type.as_deref())
        .unwrap_or(MEDIA_TYPE_OCI_MANIFEST);
    let pushed = retry
        .run("push manifest", || {
            target_client.push_manifest(
                &target_ref.repo,
                target_ref.manifest_reference(),
                media_type,
                &fetched.bytes,
            )
        })
        .await
        .with_context(|| format!("push manifest to {target_ref}"))?;

    info!(target = %target_ref, manifest = %pushed, layers = manifest.layers.len(), "copy complete");
    Ok(())
}

/// Copy one blob from the source repo to the target repo. Order of preference:
/// skip if the target already has it (HEAD-dedup), cross-repo mount when both
/// repos are on the same registry, else download to `staging` and re-push.
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
    if target_client.head_blob(target_repo, digest).await? {
        debug!(%digest, "blob already present in target; skipping");
        return Ok(());
    }
    if same_registry
        && source_repo != target_repo
        && target_client
            .mount_blob(target_repo, digest, source_repo)
            .await
            .unwrap_or(false)
    {
        debug!(%digest, from = %source_repo, "cross-repo mounted blob");
        return Ok(());
    }
    let tmp = staging.join(blob_hex(digest));
    source_client
        .get_blob_to_file(source_repo, digest, &tmp)
        .await
        .with_context(|| format!("download blob {digest}"))?;
    retry
        .run("copy blob", || {
            target_client.push_blob_file(target_repo, &tmp)
        })
        .await
        .with_context(|| format!("push blob {digest}"))?;
    let _ = std::fs::remove_file(&tmp);
    Ok(())
}

fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("create work directory {}", path.display()))
}

pub fn plan(args: &CopyArgs) -> Result<CopyPlan> {
    validate_platform_selection(args.all_platforms, args.platform.as_deref())?;
    let _ = resolve_backend_config(
        args.source_backend_type,
        args.source_backend_config.as_deref(),
        args.source_backend_config_file.as_deref(),
        "source-",
    )?;

    Ok(CopyPlan {
        source: args.source.clone(),
        target: args.target.clone(),
        platform: resolve_platform(args.platform.as_deref()),
        all_platforms: args.all_platforms,
        push_chunk_size: args.push_chunk_size.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::default_platform;

    fn base_args() -> CopyArgs {
        CopyArgs {
            source: "registry.example.com/base:latest".to_string(),
            target: Some("registry.example.com/base:copy".to_string()),
            source_insecure: false,
            target_insecure: false,
            source_backend_type: None,
            source_backend_config: None,
            source_backend_config_file: None,
            all_platforms: false,
            platform: None,
            push_chunk_size: "0MB".to_string(),
            work_dir: PathBuf::from("./tmp"),
            nydus_image: PathBuf::from("nydus-image"),
        }
    }

    #[test]
    fn builds_copy_plan_from_args() {
        let mut args = base_args();
        args.push_chunk_size = "64MB".to_string();

        let plan = plan(&args).unwrap();

        assert_eq!(plan.source, "registry.example.com/base:latest");
        assert_eq!(
            plan.target.as_deref(),
            Some("registry.example.com/base:copy")
        );
        assert_eq!(plan.push_chunk_size, "64MB");
    }

    #[test]
    fn rejects_all_platforms_with_custom_platform() {
        let mut args = base_args();
        args.all_platforms = true;
        args.platform = Some("linux/amd64".to_string());

        let err = plan(&args).unwrap_err();

        assert!(
            err.to_string()
                .contains("--all-platforms conflicts with --platform")
        );
    }

    #[test]
    fn resolves_default_platform_when_unset() {
        let plan = plan(&base_args()).unwrap();
        assert_eq!(plan.platform, default_platform());
    }
}
