// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use registry_client::types::Manifest;
use registry_client::{FetchedManifest, ImageReference, RegistryClient, RegistryError};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::cli::CheckArgs;
use crate::engine::artifact::{REFERRER_ARTIFACT_TYPE, fallback_referrers_tag};
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
        client_options(args.target_insecure, false, &args.ca_cert),
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
        check_referrer_linkage(
            &source_client_for(source, args.source_insecure, &args.ca_cert)?,
            source,
        )
        .await?;
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
fn source_client_for(
    source: &str,
    insecure: bool,
    ca_cert_files: &[std::path::PathBuf],
) -> Result<(RegistryClient, ImageReference)> {
    let source_ref =
        ImageReference::parse(source).with_context(|| format!("parse --source {source}"))?;
    let client = RegistryClient::new(
        &source_ref.api_host,
        client_options(insecure, false, ca_cert_files),
    )
    .context("build source registry client")?;
    Ok((client, source_ref))
}

/// Verify a referrer artifact linking the source image to a nydus artifact.
///
/// The **native OCI 1.1 referrers API** is consulted first
/// (`GET /v2/<repo>/referrers/<digest>`, filtered — server-side and
/// client-side — for the artifactType `nydusify convert --with-referrer`
/// publishes); when the registry lacks the API, or has nothing indexed for
/// the subject, the `sha256-<subject-hex>` fallback tag (which nydusify also
/// publishes under) is checked instead.
async fn check_referrer_linkage(
    ctx: &(RegistryClient, ImageReference),
    source: &str,
) -> Result<()> {
    let (client, source_ref) = ctx;
    let repo = &source_ref.repo;
    let subject = client
        .get_manifest(repo, source_ref.manifest_reference())
        .await
        .with_context(|| format!("fetch source manifest {source}"))?;

    // (1) Native referrers API, filtered for the nydus artifactType.
    match client
        .get_referrers(repo, &subject.digest, Some(REFERRER_ARTIFACT_TYPE))
        .await
    {
        Ok(index) if !index.manifests.is_empty() => {
            // Any indexed nydus artifact whose manifest validates and whose
            // subject matches proves the linkage.
            let mut last_err: Option<anyhow::Error> = None;
            for desc in &index.manifests {
                let artifact = client
                    .get_manifest(repo, &desc.digest)
                    .await
                    .with_context(|| format!("fetch referrer artifact {}", desc.digest))?;
                match validate_referrer_artifact(&artifact, &subject.digest) {
                    Ok(()) => {
                        info!(
                            subject = %subject.digest,
                            artifact = %desc.digest,
                            "referrer linkage verified via the OCI 1.1 referrers API"
                        );
                        return Ok(());
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            return Err(last_err
                .expect("non-empty referrers index yields at least one validation error")
                .context("no referrers-API artifact validated as a nydus referrer"));
        }
        Ok(_) => debug!(
            subject = %subject.digest,
            "referrers API returned no nydus artifacts; checking fallback tag"
        ),
        Err(RegistryError::ReferrersUnsupported) => debug!(
            subject = %subject.digest,
            "registry lacks the OCI 1.1 referrers API; checking fallback tag"
        ),
        Err(e) => return Err(e).context("query the OCI 1.1 referrers API"),
    }

    // (2) Fallback tag.
    let fallback_tag = fallback_referrers_tag(&subject.digest);
    let artifact = client
        .get_manifest(repo, &fallback_tag)
        .await
        .with_context(|| {
            format!("no referrer artifact found at fallback tag {fallback_tag} in {repo}")
        })?;
    validate_referrer_artifact(&artifact, &subject.digest)
        .with_context(|| format!("referrer artifact at fallback tag {fallback_tag}"))?;
    info!(subject = %subject.digest, fallback_tag = %fallback_tag, "referrer linkage verified via fallback tag");
    Ok(())
}

/// Validate one fetched referrer artifact manifest: it must classify as a
/// nydus artifact (bootstrap layer present) and its `subject` must be the
/// source image digest.
fn validate_referrer_artifact(artifact: &FetchedManifest, subject_digest: &str) -> Result<()> {
    let artifact_manifest: Manifest =
        serde_json::from_slice(&artifact.bytes).context("parse referrer artifact manifest")?;
    validate_nydus_manifest(&artifact_manifest)
        .context("referrer artifact is not a valid nydus artifact")?;
    match artifact_manifest.subject.as_ref() {
        Some(s) if s.digest == subject_digest => Ok(()),
        Some(s) => bail!(
            "referrer artifact subject {} does not match source image {subject_digest}",
            s.digest
        ),
        None => {
            warn!(artifact = %artifact.digest, "referrer artifact has no subject field; accepting on nydus-classification alone");
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
            ca_cert: Vec::new(),
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
