// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use registry_client::types::Manifest;
use registry_client::{ImageReference, RegistryClient};
use serde::Serialize;
use tracing::{info, warn};

use crate::cli::CheckArgs;
use crate::engine::artifact::fallback_referrers_tag;
use crate::engine::manifest::validate_nydus_manifest;
use crate::engine::oci::{client_options, fetch_platform_manifest};

use super::common::resolve_backend_config;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CheckPlan {
    pub source: Option<String>,
    pub target: String,
    pub platform: String,
    pub multi_platform: bool,
}

pub async fn run(args: CheckArgs) -> Result<()> {
    let plan = plan(&args)?;

    let target_ref = ImageReference::parse(&plan.target)
        .with_context(|| format!("parse --target {}", plan.target))?;
    let target_client = RegistryClient::new(
        &target_ref.api_host,
        client_options(args.target_insecure, false),
    )
    .context("build target registry client")?;

    info!(target = %target_ref, platform = %plan.platform, "checking nydus image");

    // (1) Pull the target manifest and validate it is a nydus image.
    let fetched = fetch_platform_manifest(
        &target_client,
        &target_ref.repo,
        target_ref.manifest_reference(),
        &plan.platform,
    )
    .await
    .with_context(|| format!("fetch target manifest {target_ref}"))?;
    let manifest: Manifest =
        serde_json::from_slice(&fetched.bytes).context("parse target image manifest")?;
    let bootstrap = validate_nydus_manifest(&manifest)
        .with_context(|| format!("{target_ref} is not a valid nydus image"))?;
    info!(bootstrap = %bootstrap.digest, "target is a nydus image");

    // (2) Referrer linkage: when --source is given, the target is expected to be
    // attached to the source image as a referrer artifact. Verify it exists and
    // its subject matches the source manifest digest.
    if let Some(source) = &plan.source {
        check_referrer_linkage(&source_client_for(source, args.source_insecure)?, source).await?;
    }

    // (3) Download the bootstrap and run `nydus-image check` on it.
    ensure_dir(&args.work_dir)?;
    let bootstrap_path = args.work_dir.join("bootstrap");
    target_client
        .get_blob_to_file(&target_ref.repo, &bootstrap.digest, &bootstrap_path)
        .await
        .with_context(|| format!("download bootstrap {}", bootstrap.digest))?;
    run_nydus_image_check(&args.nydus_image, &bootstrap_path)?;

    // NOTE: no mount-diff check (comparing the mounted nydus rootfs against
    // the source rootfs). That needs a nydusd mount + source extraction.
    info!(target = %target_ref, "check passed: valid nydus image, bootstrap verified");
    Ok(())
}

/// Build a registry client for the source image reference.
fn source_client_for(source: &str, insecure: bool) -> Result<(RegistryClient, ImageReference)> {
    let source_ref =
        ImageReference::parse(source).with_context(|| format!("parse --source {source}"))?;
    let client = RegistryClient::new(&source_ref.api_host, client_options(insecure, false))
        .context("build source registry client")?;
    Ok((client, source_ref))
}

/// Verify a referrer artifact linking the source image to a nydus artifact.
///
/// registry-client has no referrers-API (`GET /v2/<repo>/referrers/<digest>`)
/// method, so this checks only the `sha256-<subject-hex>` fallback tag in the
/// source repo (which nydusify itself publishes). A registry that exposes the
/// artifact *only* via the native referrers API (no fallback tag) is not
/// detected here.
async fn check_referrer_linkage(
    ctx: &(RegistryClient, ImageReference),
    source: &str,
) -> Result<()> {
    let (client, source_ref) = ctx;
    let subject = client
        .get_manifest(&source_ref.repo, source_ref.manifest_reference())
        .await
        .with_context(|| format!("fetch source manifest {source}"))?;

    let fallback_tag = fallback_referrers_tag(&subject.digest);
    let artifact = client
        .get_manifest(&source_ref.repo, &fallback_tag)
        .await
        .with_context(|| {
            format!(
                "no referrer artifact found at fallback tag {fallback_tag} in {} \
                 (referrers-API-only registries are not checked; see registry-client gap)",
                source_ref.repo
            )
        })?;
    let artifact_manifest: Manifest =
        serde_json::from_slice(&artifact.bytes).context("parse referrer artifact manifest")?;

    // It must classify as a nydus artifact (bootstrap layer present)...
    validate_nydus_manifest(&artifact_manifest)
        .context("referrer artifact is not a valid nydus artifact")?;
    // ...and its subject must be the source image.
    match artifact_manifest.subject.as_ref() {
        Some(s) if s.digest == subject.digest => {
            info!(subject = %subject.digest, fallback_tag = %fallback_tag, "referrer linkage verified");
            Ok(())
        }
        Some(s) => bail!(
            "referrer artifact subject {} does not match source image {}",
            s.digest,
            subject.digest
        ),
        None => {
            warn!(fallback_tag = %fallback_tag, "referrer artifact has no subject field; accepting on nydus-classification alone");
            Ok(())
        }
    }
}

/// Run `nydus-image check --bootstrap <path>`, capturing stderr on failure
/// (mirrors the subprocess convention in `snapshotter/src/local_accel.rs`).
fn run_nydus_image_check(nydus_image: &Path, bootstrap: &Path) -> Result<()> {
    let args: Vec<OsString> = vec!["check".into(), "--bootstrap".into(), bootstrap.into()];
    let output = Command::new(nydus_image)
        .args(&args)
        .output()
        .with_context(|| format!("spawn `{}` check", nydus_image.display()))?;
    if !output.status.success() {
        bail!(
            "nydus-image check failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("create work directory {}", path.display()))
}

pub fn plan(args: &CheckArgs) -> Result<CheckPlan> {
    let _ = resolve_backend_config(
        args.source_backend_type,
        args.source_backend_config.as_deref(),
        args.source_backend_config_file.as_deref(),
        "source-",
    )?;
    let _ = resolve_backend_config(
        args.target_backend_type,
        args.target_backend_config.as_deref(),
        args.target_backend_config_file.as_deref(),
        "target-",
    )?;

    Ok(CheckPlan {
        source: args.source.clone(),
        target: args.target.clone(),
        platform: args.platform.clone(),
        multi_platform: args.multi_platform,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::{BackendType, default_platform};

    fn base_args() -> CheckArgs {
        CheckArgs {
            source: Some("registry.example.com/base:latest".to_string()),
            target: "registry.example.com/base:latest-nydus".to_string(),
            source_insecure: false,
            target_insecure: false,
            source_backend_type: None,
            source_backend_config: None,
            source_backend_config_file: None,
            target_backend_type: None,
            target_backend_config: None,
            target_backend_config_file: None,
            multi_platform: false,
            platform: default_platform(),
            work_dir: PathBuf::from("./output"),
            nydus_image: PathBuf::from("nydus-image"),
            nydusd: PathBuf::from("nydusd"),
        }
    }

    #[test]
    fn builds_check_plan_from_args() {
        let mut args = base_args();
        args.multi_platform = true;

        let plan = plan(&args).unwrap();

        assert_eq!(
            plan.source.as_deref(),
            Some("registry.example.com/base:latest")
        );
        assert_eq!(plan.target, "registry.example.com/base:latest-nydus");
        assert!(plan.multi_platform);
    }

    #[test]
    fn rejects_target_backend_config_without_type() {
        let mut args = base_args();
        args.target_backend_config = Some("{}".to_string());

        let err = plan(&args).unwrap_err();

        assert!(
            err.to_string()
                .contains("--target-backend-type is required")
        );
    }

    #[test]
    fn accepts_registry_target_without_backend_config() {
        let mut args = base_args();
        args.target_backend_type = Some(BackendType::Registry);

        assert!(plan(&args).is_ok());
    }
}
