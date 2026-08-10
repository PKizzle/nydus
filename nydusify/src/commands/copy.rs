// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use registry_client::types::{MEDIA_TYPE_OCI_INDEX, MEDIA_TYPE_OCI_MANIFEST, Manifest};
use registry_client::{ImageReference, Index, RegistryClient};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::cli::CopyArgs;
use crate::engine::oci::{blob_hex, client_options, is_index, select_platform};
use crate::engine::oci_archive::{self, ArchiveBlob};
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

    // `file://<path>` on either side means a local OCI layout tarball rather
    // than a registry, so those are resolved before parsing anything as a
    // reference (ImageReference rejects a scheme outright).
    let source_archive = oci_archive::local_path(&plan.source).context("parse --source")?;
    let target_archive = oci_archive::local_path(&target).context("parse --target")?;

    ensure_dir(&args.work_dir)?;
    let staging = tempfile::Builder::new()
        .prefix("nydusify-copy-")
        .tempdir_in(&args.work_dir)
        .with_context(|| format!("create staging dir in {}", args.work_dir.display()))?;

    if let Some(archive) = source_archive {
        return copy_from_archive(
            &args,
            &plan,
            &archive,
            target_archive.as_deref(),
            &target,
            staging.path(),
        )
        .await;
    }

    let source_ref = ImageReference::parse(&plan.source)
        .with_context(|| format!("parse --source {}", plan.source))?;

    let source_client = RegistryClient::new(
        &source_ref.api_host,
        client_options(
            args.source_insecure,
            args.plain_http || args.source_plain_http,
            &args.ca_cert,
        ),
    )
    .context("build source registry client")?;
    info!(source = %source_ref, target = %target, platform = %plan.platform, "copying image");

    let retry = RetryPolicy::default();

    // Fetch the top-level reference; if it is a multi-platform index, resolve to
    // a single platform manifest and warn loudly that the copied tag will NOT be
    // multi-arch (a real degradation of the source).
    let top = source_client
        .get_manifest(&source_ref.repo, source_ref.manifest_reference())
        .await
        .with_context(|| format!("fetch source manifest {source_ref}"))?;
    let top_is_index = is_index(top.content_type.as_deref(), &top.bytes);

    // `--all-platforms` copies the index whole: every entry, then the index
    // bytes verbatim. Handled before the single-platform path because that path
    // reduces the source to one manifest and cannot be reused here.
    if plan.all_platforms && top_is_index {
        if let Some(archive) = &target_archive {
            bail!(
                "--all-platforms cannot export to the OCI archive {}: the layout would need one \
                 manifest per platform and `export` writes a single image (follow-up); copy to a \
                 registry, or pick one platform with --platform",
                archive.display()
            );
        }
        let index: Index =
            serde_json::from_slice(&top.bytes).context("parse source image index")?;
        let target_ref =
            ImageReference::parse(&target).with_context(|| format!("parse --target {target}"))?;
        let target_client = RegistryClient::new(
            &target_ref.api_host,
            client_options(
                args.target_insecure,
                args.plain_http || args.target_plain_http,
                &args.ca_cert,
            ),
        )
        .context("build target registry client")?;
        let same_registry = source_ref.api_host == target_ref.api_host;
        return copy_index_all_platforms(
            &source_client,
            &source_ref,
            &target_client,
            &target_ref,
            same_registry,
            &index,
            &top,
            staging.path(),
            &retry,
        )
        .await;
    }

    let fetched = if top_is_index {
        // `--all-platforms` cannot reach here: the branch above returns for an
        // index source, so this is the single-platform path by construction.
        warn!(
            source = %source_ref,
            platform = %plan.platform,
            "source is a multi-platform index; copying only the {} manifest — the copied tag will be single-arch, not a full index. Pass --all-platforms to copy every entry instead",
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
        // A single-manifest source has no platforms to fan out over, so
        // `--all-platforms` degrades to an ordinary copy. Say so: silence here
        // reads as "copied every platform" when there was only ever one.
        if plan.all_platforms {
            warn!(
                source = %source_ref,
                "--all-platforms was passed but the source is a single manifest, not an index; copying it as-is"
            );
        }
        top
    };
    let manifest: Manifest =
        serde_json::from_slice(&fetched.bytes).context("parse source image manifest")?;

    // Registry -> local archive: stage every blob, then write the layout tar.
    if let Some(archive) = &target_archive {
        return export_from_registry(
            &source_client,
            &source_ref,
            &manifest,
            &fetched,
            archive,
            staging.path(),
        )
        .await;
    }

    let target_ref =
        ImageReference::parse(&target).with_context(|| format!("parse --target {target}"))?;
    let target_client = RegistryClient::new(
        &target_ref.api_host,
        client_options(
            args.target_insecure,
            args.plain_http || args.target_plain_http,
            &args.ca_cert,
        ),
    )
    .context("build target registry client")?;
    let same_registry = source_ref.api_host == target_ref.api_host;

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

/// The index entries to copy: every descriptor, in index order, with repeated
/// digests collapsed to their first occurrence.
///
/// An index can legitimately name one digest twice -- two platform entries
/// sharing an identical manifest, or an attestation whose subject is another
/// entry. Copying is idempotent, so a duplicate is only wasted round trips, but
/// on a 50-layer image those round trips are the whole cost.
fn distinct_entries(index: &Index) -> Vec<&registry_client::types::Descriptor> {
    let mut seen = std::collections::HashSet::new();
    index
        .manifests
        .iter()
        .filter(|d| seen.insert(d.digest.as_str()))
        .collect()
}

/// Copy every entry of a multi-platform index, then the index itself.
///
/// Two invariants make the copied tag a faithful replica rather than a lookalike:
///
///   * children are pushed BY DIGEST, never by tag, so the index's descriptors
///     resolve in the target exactly as they did in the source; and
///   * the index bytes go up VERBATIM, so the copied tag keeps the source
///     index's digest. Anything pinned to `repo@sha256:<index>` still resolves,
///     and re-running the copy is a no-op instead of churning the digest.
///
/// Entries without a platform, and `unknown/unknown` entries (how buildkit
/// attaches SBOM/provenance attestations), are copied like any other manifest.
/// They are referenced by the index, so dropping them would leave it pointing at
/// blobs the target does not have -- a broken tag that only fails later, when
/// something actually resolves that descriptor.
#[allow(clippy::too_many_arguments)]
async fn copy_index_all_platforms(
    source_client: &RegistryClient,
    source_ref: &ImageReference,
    target_client: &RegistryClient,
    target_ref: &ImageReference,
    same_registry: bool,
    index: &Index,
    top: &registry_client::FetchedManifest,
    staging: &Path,
    retry: &RetryPolicy,
) -> Result<()> {
    if index.manifests.is_empty() {
        bail!("source index {source_ref} lists no manifests; nothing to copy");
    }
    info!(
        source = %source_ref,
        target = %target_ref,
        entries = index.manifests.len(),
        "copying every index entry"
    );

    let entries = distinct_entries(index);
    if entries.len() < index.manifests.len() {
        debug!(
            total = index.manifests.len(),
            distinct = entries.len(),
            "index names some digests more than once; copying each only once"
        );
    }
    for desc in entries {
        let child = source_client
            .get_manifest(&source_ref.repo, &desc.digest)
            .await
            .with_context(|| format!("fetch index entry {}", desc.digest))?;

        // A nested index (an index naming another index) is legal OCI but not
        // something any registry in play here produces. Refuse it rather than
        // push a parent whose grandchildren were never copied -- that yields a
        // tag which resolves until something walks the second level.
        if is_index(child.content_type.as_deref(), &child.bytes) {
            bail!(
                "index entry {} is itself an index; nested indexes are not supported (follow-up). \
                 Copy that entry directly, or select one platform with --platform",
                desc.digest
            );
        }

        let manifest: Manifest = serde_json::from_slice(&child.bytes)
            .with_context(|| format!("parse index entry {}", desc.digest))?;
        let platform = desc
            .platform
            .as_ref()
            .map(|p| format!("{}/{}", p.os, p.architecture))
            .unwrap_or_else(|| "<no platform>".to_string());
        debug!(digest = %desc.digest, %platform, layers = manifest.layers.len(), "copying index entry");

        for blob in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
            copy_blob(
                source_client,
                &source_ref.repo,
                target_client,
                &target_ref.repo,
                same_registry,
                &blob.digest,
                staging,
                retry,
            )
            .await
            .with_context(|| format!("copy blob {} of entry {}", blob.digest, desc.digest))?;
        }

        // By digest, and with the child's own media type -- re-typing a docker
        // schema-2 manifest as OCI would change its bytes, hence its digest, and
        // the index descriptor would no longer point at it.
        let media_type = manifest
            .media_type
            .as_deref()
            .or(child.content_type.as_deref())
            .unwrap_or(MEDIA_TYPE_OCI_MANIFEST);
        retry
            .run("push index entry", || {
                target_client.push_manifest(
                    &target_ref.repo,
                    &desc.digest,
                    media_type,
                    &child.bytes,
                )
            })
            .await
            .with_context(|| format!("push index entry {} to {target_ref}", desc.digest))?;
    }

    // The index last: every descriptor it names now exists in the target.
    let index_media_type = index
        .media_type
        .as_deref()
        .or(top.content_type.as_deref())
        .unwrap_or(MEDIA_TYPE_OCI_INDEX);
    let pushed = retry
        .run("push index", || {
            target_client.push_manifest(
                &target_ref.repo,
                target_ref.manifest_reference(),
                index_media_type,
                &top.bytes,
            )
        })
        .await
        .with_context(|| format!("push index to {target_ref}"))?;

    if pushed != top.digest {
        warn!(
            source_digest = %top.digest,
            target_digest = %pushed,
            "target registry re-serialised the index; the copied tag does NOT keep the source digest"
        );
    }
    info!(
        target = %target_ref,
        manifest = %pushed,
        entries = index.manifests.len(),
        "copy complete: full index"
    );
    Ok(())
}

/// Registry -> `file://` archive: download the manifest's blobs and write an
/// OCI layout tarball.
async fn export_from_registry(
    source_client: &RegistryClient,
    source_ref: &ImageReference,
    manifest: &Manifest,
    fetched: &registry_client::FetchedManifest,
    archive: &Path,
    staging: &Path,
) -> Result<()> {
    let mut blobs = Vec::with_capacity(manifest.layers.len() + 1);
    for desc in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        let path = staging.join(blob_hex(&desc.digest));
        source_client
            .get_blob_to_file(&source_ref.repo, &desc.digest, &path)
            .await
            .with_context(|| format!("download blob {}", desc.digest))?;
        blobs.push(ArchiveBlob {
            digest: desc.digest.clone(),
            size: desc.size,
            path,
        });
    }

    let media_type = manifest
        .media_type
        .as_deref()
        .or(fetched.content_type.as_deref())
        .unwrap_or(MEDIA_TYPE_OCI_MANIFEST);
    oci_archive::export(
        archive,
        &fetched.bytes,
        media_type,
        &source_ref.to_string(),
        &blobs,
    )
    .with_context(|| format!("write archive {}", archive.display()))?;

    info!(
        archive = %archive.display(),
        layers = manifest.layers.len(),
        "exported image to OCI archive"
    );
    Ok(())
}

/// `file://` archive -> registry (or another archive): unpack the layout and
/// push, or copy the file when both ends are archives.
async fn copy_from_archive(
    args: &CopyArgs,
    plan: &CopyPlan,
    archive: &Path,
    target_archive: Option<&Path>,
    target: &str,
    staging: &Path,
) -> Result<()> {
    let unpacked = staging.join("layout");
    let imported = oci_archive::import(archive, &unpacked)
        .with_context(|| format!("import archive {}", archive.display()))?;
    info!(
        archive = %archive.display(),
        ref_name = imported.ref_name.as_deref().unwrap_or("<none>"),
        "imported image from OCI archive"
    );

    // Archive -> archive is a straight copy; re-serialising would only risk
    // changing bytes that are already exactly what we would write.
    if let Some(out) = target_archive {
        std::fs::copy(archive, out)
            .with_context(|| format!("copy archive {} -> {}", archive.display(), out.display()))?;
        info!(archive = %out.display(), "wrote OCI archive");
        return Ok(());
    }

    let target_ref =
        ImageReference::parse(target).with_context(|| format!("parse --target {target}"))?;
    let client = RegistryClient::new(
        &target_ref.api_host,
        client_options(
            args.target_insecure,
            args.plain_http || args.target_plain_http,
            &args.ca_cert,
        ),
    )
    .context("build target registry client")?;
    let retry = RetryPolicy::default();

    let manifest = &imported.manifest;
    for desc in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        if client
            .head_blob(&target_ref.repo, &desc.digest)
            .await
            .unwrap_or(false)
        {
            debug!(digest = %desc.digest, "blob already present in target; skipping");
            continue;
        }
        let path = imported.blob_path(&desc.digest)?;
        retry
            .run("push archived blob", || {
                client.push_blob_file(&target_ref.repo, &path)
            })
            .await
            .with_context(|| format!("push blob {}", desc.digest))?;
    }

    let media_type = manifest
        .media_type
        .as_deref()
        .unwrap_or(&imported.descriptor.media_type);
    let pushed = retry
        .run("push manifest", || {
            client.push_manifest(
                &target_ref.repo,
                target_ref.manifest_reference(),
                media_type,
                &imported.manifest_bytes,
            )
        })
        .await
        .with_context(|| format!("push manifest to {target_ref}"))?;

    info!(
        target = %target_ref,
        manifest = %pushed,
        layers = manifest.layers.len(),
        platform = %plan.platform,
        "copy complete"
    );
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
            plain_http: false,
            source_plain_http: false,
            target_plain_http: false,
            ca_cert: Vec::new(),
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

    /// `--all-platforms` used to be rejected outright in `run`. Planning must now
    /// accept it, so this is the regression guard for that bail coming back.
    #[test]
    fn accepts_all_platforms() {
        let mut args = base_args();
        args.all_platforms = true;

        let plan = plan(&args).unwrap();

        assert!(plan.all_platforms);
    }

    fn index_of(digests: &[&str]) -> Index {
        Index {
            schema_version: 2,
            media_type: Some(MEDIA_TYPE_OCI_INDEX.to_string()),
            manifests: digests
                .iter()
                .map(|d| registry_client::types::Descriptor {
                    digest: (*d).to_string(),
                    ..Default::default()
                })
                .collect(),
            annotations: None,
        }
    }

    #[test]
    fn distinct_entries_keeps_index_order() {
        let index = index_of(&["sha256:aaa", "sha256:bbb", "sha256:ccc"]);

        let got: Vec<&str> = distinct_entries(&index)
            .iter()
            .map(|d| d.digest.as_str())
            .collect();

        assert_eq!(got, ["sha256:aaa", "sha256:bbb", "sha256:ccc"]);
    }

    /// A repeated digest is one manifest, so it must be pushed once -- and the
    /// FIRST occurrence is the one kept, so ordering stays stable.
    #[test]
    fn distinct_entries_collapses_repeats() {
        let index = index_of(&["sha256:aaa", "sha256:bbb", "sha256:aaa", "sha256:bbb"]);

        let got: Vec<&str> = distinct_entries(&index)
            .iter()
            .map(|d| d.digest.as_str())
            .collect();

        assert_eq!(got, ["sha256:aaa", "sha256:bbb"]);
    }
}
