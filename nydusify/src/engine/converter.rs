// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! End-to-end `nydusify convert` pipeline: pull a source OCI image, drive
//! `nydus-image` (subprocess, mirroring `snapshotter/src/local_accel.rs`) to
//! build a RAFS v6 artifact, and push the nydus data blobs + bootstrap + image
//! manifest to the target registry.
//!
//! Two modes:
//!
//! * **`--oci-ref`** (zran): `nydus-image create --type targz-ref` per layer,
//!   then `merge --original-blob-ids <gzip-digests>`. The data blobs are the
//!   *original gzip layers* (mounted from the source repo on a same-registry
//!   target, else re-pushed) plus tiny per-layer zran index blobs.
//! * **standard**: `nydus-image create --type targz-rafs` per layer (new nydus
//!   data blobs), then `merge`.
//!
//! In both modes `--prefetch-*` (when it names concrete in-image paths) is
//! honored via `nydus-image optimize --prefetch-files`, which bakes hints into
//! the bootstrap and stages a packed prefetch blob (also pushed).
//!
//! The registry client is the `!Send` compio [`RegistryClient`]; the whole
//! pipeline runs on one thread, so it is held directly across awaits. The
//! `nydus-image` invocations are blocking subprocesses run inline between the
//! async pull/push phases.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use registry_client::types::Manifest;
use registry_client::{Descriptor, ImageReference, Index, RegistryClient};
use tracing::{debug, info, warn};

use crate::commands::convert::{ConversionMode, SourceSpec};
use crate::engine::artifact::maybe_push_referrer;
use crate::engine::bootstrap_layer;
use crate::engine::containerd_converter::ConvertRequest;
use crate::engine::manifest::{
    assemble_index, assemble_manifest, bootstrap_descriptor, config_media_type,
    data_blob_descriptor, index_media_type, manifest_media_type, rebuild_image_config,
    synthesize_image_config,
};
use crate::engine::oci::{
    all_platform_selectors, blob_hex, client_options, is_index, parse_platform_list,
    select_platform,
};
use crate::engine::oci_archive::{self, ArchiveBlob};
use crate::engine::retry::RetryPolicy;

/// A source rootfs layer pulled to disk.
#[derive(Clone, Debug)]
struct PulledLayer {
    /// OCI digest (`sha256:<hex>`) of the (gzip) layer blob.
    digest: String,
    /// On-disk path of the downloaded layer blob.
    path: PathBuf,
}

/// One unit of the merge, in stacking order (lowest first).
///
/// Layers and directories are interchangeable from `merge`'s point of view: each becomes
/// one bootstrap, and the merge stacks them in the order given. What differs is only how
/// the bootstrap is produced.
#[derive(Clone, Debug)]
enum BuildInput {
    /// A layer of a pulled image source.
    Layer(PulledLayer),
    /// A local directory, built into a nydus layer directly.
    Directory(PathBuf),
}

impl BuildInput {
    /// A short, filesystem-safe tag for this input's scratch directory.
    ///
    /// Only has to be unique among the inputs, and the index prefixed by the caller
    /// already guarantees that; this exists to keep the workspace readable when a
    /// conversion is being debugged.
    fn slug(&self) -> String {
        match self {
            BuildInput::Layer(layer) => blob_hex(&layer.digest).to_string(),
            BuildInput::Directory(dir) => dir
                .file_name()
                .map(|n| {
                    n.to_string_lossy()
                        .replace(|c: char| !c.is_alphanumeric(), "_")
                })
                .unwrap_or_else(|| "dir".to_string()),
        }
    }

    /// How this input is named in an error, so a failed build says which source it was.
    fn describe(&self) -> String {
        match self {
            BuildInput::Layer(layer) => format!("layer {}", layer.digest),
            BuildInput::Directory(dir) => format!("directory {}", dir.display()),
        }
    }
}

/// The pulled source image (single platform).
struct PulledSource {
    /// Descriptor the referrer artifact is published against. For a
    /// single-platform convert of a single-arch source this is the source
    /// manifest; for one platform of a multi-arch source it is that
    /// platform's manifest (so a merged conversion attaches one referrer per
    /// platform, each resolvable from its own subject).
    ///
    /// `None` for a directory-only conversion: there is no source manifest to be the subject
    /// of a referrer, which is why `--with-referrer` is refused for one.
    referrer_subject: Option<Descriptor>,
    /// The platform this manifest targets (index entry + reporting).
    platform: registry_client::types::Platform,
    /// Sum of the source layer (compressed) sizes, for `--output-json`.
    source_size: u64,
    /// Raw image-config JSON, reused verbatim as the nydus image config.
    config_bytes: Vec<u8>,
    /// The resolved per-platform source manifest, byte-identical as fetched.
    /// `--attach-oci-manifest` republishes it beside the nydus manifest.
    manifest_bytes: Vec<u8>,
    /// When the source tag resolved through an index: its entries, verbatim.
    /// `--attach-oci-manifest` preserves every one of them -- replacing a multi-arch
    /// tag with a single-arch index would silently break the other architectures.
    source_index_entries: Option<Vec<Descriptor>>,
    layers: Vec<PulledLayer>,
}

/// Output of the `nydus-image` build stage.
struct ConversionOutput {
    /// Merged RAFS bootstrap.
    bootstrap: PathBuf,
    /// Newly-created nydus data blobs to push from disk (zran index blobs in
    /// `--oci-ref`, full data blobs in standard mode, plus an optional prefetch
    /// blob). Each file name is the blob id.
    new_blobs: Vec<PathBuf>,
    /// `--oci-ref` only: the original gzip layers reused as data blobs
    /// (cross-repo mounted on a same-registry target, else re-pushed).
    reused_layers: Vec<PulledLayer>,
}

/// Run the full convert pipeline. `workspace` is a temp dir under `--work-dir`.
pub async fn run_conversion(request: &ConvertRequest, workspace: &Path) -> Result<()> {
    reject_unsupported(request)?;
    let started = std::time::Instant::now();

    // Both are `None` when every `--source` is a local directory: there is no source image to
    // parse and no registry to pull one from. Every option that would need them is refused at
    // plan time, so the pipeline below only has to skip the pull.
    let source_ref = request
        .source
        .as_deref()
        .map(|source| {
            ImageReference::parse(source).with_context(|| format!("parse --source {source}"))
        })
        .transpose()?;
    let target_ref = ImageReference::parse(&request.target)
        .with_context(|| format!("parse --target {}", request.target))?;

    let source_client = source_ref
        .as_ref()
        .map(|source_ref| {
            RegistryClient::new(
                &source_ref.api_host,
                client_options(
                    request.source_insecure,
                    request.source_plain_http,
                    &request.ca_cert_files,
                ),
            )
            .context("build source registry client")
        })
        .transpose()?;
    let target_client = RegistryClient::new(
        &target_ref.api_host,
        client_options(
            request.target_insecure,
            request.target_plain_http,
            &request.ca_cert_files,
        ),
    )
    .context("build target registry client")?;
    let same_registry = source_ref
        .as_ref()
        .is_some_and(|s| s.api_host == target_ref.api_host);
    let retry = RetryPolicy::from_flags(request.push_retry_count, &request.push_retry_delay);

    // Resolve which platforms to convert from the top-level source reference.
    let plan = match (&source_client, &source_ref) {
        (Some(client), Some(source_ref)) => {
            resolve_platform_plan(request, client, source_ref).await?
        }
        // Directory-only: there is no index to enumerate, and a multi-platform selection was
        // refused at plan time, so `--platform` (or the host default) is the whole answer.
        _ => PlatformPlan {
            selectors: parse_platform_list(&request.platforms)?,
        },
    };

    if plan.selectors.len() == 1 {
        // Single platform: push the manifest directly at the target tag —
        // byte-for-byte the pre-multi-platform behavior (no index wrapper).
        let outcome = convert_one_platform(
            request,
            source_client.as_ref(),
            &target_client,
            source_ref.as_ref(),
            &target_ref,
            same_registry,
            &plan.selectors[0],
            PushTarget::Tag,
            &workspace.join("p0"),
            &retry,
        )
        .await?;
        if let Some(path) = &request.output_json {
            write_output_json(
                path,
                &target_ref,
                std::slice::from_ref(&outcome),
                started.elapsed().as_secs_f64(),
            )?;
        }
        info!(
            target = %target_ref,
            manifest = %outcome.manifest.digest,
            data_blobs = outcome.data_blob_count,
            "convert complete: pushed nydus image"
        );
        return Ok(());
    }

    // Multi-platform: --merge-platform is required (mirrors the Go tool — we do
    // not silently pick one, nor push N tag-less manifests with no index to
    // find them by).
    if !request.driver.merge_manifest {
        bail!(
            "source resolves to {} platforms ({}); pass --merge-platform to publish them as one \
             multi-arch image, or --platform to pick one",
            plan.selectors.len(),
            plan.selectors.join(", ")
        );
    }

    let mut outcomes = Vec::with_capacity(plan.selectors.len());
    for (i, selector) in plan.selectors.iter().enumerate() {
        info!(platform = %selector, "converting platform {}/{}", i + 1, plan.selectors.len());
        // Per-platform manifests are pushed BY DIGEST (only the index carries
        // the tag), each in its own workspace subdir so builds don't collide.
        let outcome = convert_one_platform(
            request,
            source_client.as_ref(),
            &target_client,
            source_ref.as_ref(),
            &target_ref,
            same_registry,
            selector,
            PushTarget::ByDigest,
            &workspace.join(format!("p{i}")),
            &retry,
        )
        .await?;
        outcomes.push(outcome);
    }

    // Assemble and push the OCI image index at the target tag.
    let index_manifests: Vec<Descriptor> = outcomes
        .iter()
        .map(|o| {
            let mut d = o.manifest.clone();
            d.platform = Some(o.platform.clone());
            d
        })
        .collect();
    let index = assemble_index(request.driver.docker2oci, index_manifests);
    let index_bytes = serde_json::to_vec(&index).context("serialize multi-platform index")?;
    let index_media = index_media_type(request.driver.docker2oci);
    let index_digest = retry
        .run("push multi-platform index", || {
            target_client.push_manifest(
                &target_ref.repo,
                target_ref.manifest_reference(),
                index_media,
                &index_bytes,
            )
        })
        .await
        .with_context(|| format!("push multi-platform index to {target_ref}"))?;

    if let Some(path) = &request.output_json {
        write_output_json(
            path,
            &target_ref,
            &outcomes,
            started.elapsed().as_secs_f64(),
        )?;
    }
    info!(
        target = %target_ref,
        index = %index_digest,
        platforms = outcomes.len(),
        "convert complete: pushed multi-platform nydus image"
    );
    Ok(())
}

/// Where a converted per-platform manifest is published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PushTarget {
    /// Push at the target reference's tag (single-platform convert).
    Tag,
    /// Push by the manifest's own digest (each leaf of a multi-arch index).
    ByDigest,
}

/// One converted platform: the pushed manifest descriptor plus the accounting
/// the Go-schema `--output-json` reports.
struct PlatformOutcome {
    /// Descriptor of the pushed per-platform nydus manifest.
    manifest: Descriptor,
    /// The platform this manifest targets (for index entries + reporting).
    platform: registry_client::types::Platform,
    /// Sum of source layer (compressed) sizes.
    source_size: u64,
    /// Sum of pushed nydus content (data blobs + bootstrap + config + manifest).
    target_size: u64,
    /// Number of data blobs in the pushed manifest.
    data_blob_count: usize,
}

/// The set of platform selectors a convert request expands to.
struct PlatformPlan {
    selectors: Vec<String>,
}

/// Resolve `--platform` / `--all-platforms` against the source's top-level
/// reference into a concrete selector list.
async fn resolve_platform_plan(
    request: &ConvertRequest,
    client: &RegistryClient,
    source_ref: &ImageReference,
) -> Result<PlatformPlan> {
    let fetched = client
        .get_manifest(&source_ref.repo, source_ref.manifest_reference())
        .await
        .with_context(|| format!("fetch source manifest {source_ref}"))?;

    if !is_index(fetched.content_type.as_deref(), &fetched.bytes) {
        // A single-arch source has exactly one platform to convert. Multiple
        // requested platforms cannot be satisfied by a non-index source.
        if request.all_platforms {
            bail!(
                "--all-platforms requires a multi-arch source; {source_ref} is a single manifest"
            );
        }
        let requested = parse_platform_list(&request.platforms)?;
        if requested.len() > 1 {
            bail!(
                "--platform names {} platforms but {source_ref} is a single manifest",
                requested.len()
            );
        }
        return Ok(PlatformPlan {
            selectors: vec![requested.into_iter().next().unwrap()],
        });
    }

    let index: Index =
        serde_json::from_slice(&fetched.bytes).context("parse source image index")?;
    let selectors = if request.all_platforms {
        let all = all_platform_selectors(&index);
        if all.is_empty() {
            bail!("--all-platforms: source index {source_ref} lists no platform-tagged manifests");
        }
        all
    } else {
        // Validate every requested selector resolves in the index up front.
        let requested = parse_platform_list(&request.platforms)?;
        for sel in &requested {
            select_platform(&index, sel)?;
        }
        requested
    };
    Ok(PlatformPlan { selectors })
}

/// Convert exactly one platform end-to-end (pull → build → push, plus an
/// optional referrer) and report its accounting. Shared by the single- and
/// multi-platform paths.
#[allow(clippy::too_many_arguments)]
async fn convert_one_platform(
    request: &ConvertRequest,
    source_client: Option<&RegistryClient>,
    target_client: &RegistryClient,
    source_ref: Option<&ImageReference>,
    target_ref: &ImageReference,
    same_registry: bool,
    platform: &str,
    push_target: PushTarget,
    workspace: &Path,
    retry: &RetryPolicy,
) -> Result<PlatformOutcome> {
    std::fs::create_dir_all(workspace)
        .with_context(|| format!("create platform workspace {}", workspace.display()))?;

    // ---- pull ----
    let (source, inputs) = match &request.source_archive {
        Some(archive) => {
            let source = pull_source_from_archive(request, archive, platform, workspace)?;
            let inputs = source
                .layers
                .iter()
                .cloned()
                .map(BuildInput::Layer)
                .collect();
            (source, inputs)
        }
        None => gather_sources(request, source_client, source_ref, platform, workspace).await?,
    };
    info!(
        source = source_ref.map(|r| r.to_string()).as_deref().unwrap_or("(directories only)"),
        platform = %platform,
        sources = request.sources.len(),
        inputs = inputs.len(),
        oci_ref = request.driver.oci_ref,
        "gathered sources; building nydus artifact"
    );

    // ---- build (nydus-image subprocess) ----
    let output = build_artifact(request, &inputs, workspace)?;

    // ---- push (or write a local archive) ----
    // With --attach-oci-manifest the nydus manifest goes in by digest; the tag is taken by
    // the dual-manifest index pushed after it.
    let push_target = if request.attach_oci_manifest {
        PushTarget::ByDigest
    } else {
        push_target
    };
    let pushed = match &request.target_archive {
        Some(archive) => export_artifact(
            request,
            archive,
            &source,
            &output,
            &request.target,
            workspace,
        )?,
        None => {
            push_artifact(
                request,
                target_client,
                target_ref,
                source_ref,
                same_registry,
                &source,
                &output,
                push_target,
                retry,
            )
            .await?
        }
    };

    // ---- referrer (--with-referrer) ----
    // Data blobs in image-layer order: reused gzip layers (oci-ref) then the
    // newly-built nydus blobs. The subject is the per-platform source manifest
    // so a multi-arch conversion attaches one referrer per platform.
    let mut data_blob_files: Vec<PathBuf> = output
        .reused_layers
        .iter()
        .map(|l| l.path.clone())
        .collect();
    data_blob_files.extend(output.new_blobs.iter().cloned());
    // A referrer needs a source image to be the subject of; `--with-referrer` is refused at
    // plan time without one, so there is nothing to publish here for a directory-only convert.
    if let (Some(source_client), Some(source_ref), Some(subject)) =
        (source_client, source_ref, &source.referrer_subject)
    {
        maybe_push_referrer(
            request.driver.with_referrer,
            source_client,
            &source_ref.repo,
            &data_blob_files,
            &output.bootstrap,
            subject,
            retry,
        )
        .await?;
    }

    if request.attach_oci_manifest {
        attach_oci_manifest_and_push_index(
            target_client,
            target_ref,
            source_ref,
            same_registry,
            &source,
            &pushed.manifest,
            retry,
        )
        .await?;
    }

    Ok(PlatformOutcome {
        target_size: pushed.target_size,
        manifest: pushed.manifest,
        platform: source.platform,
        source_size: source.source_size,
        data_blob_count: output.reused_layers.len() + output.new_blobs.len(),
    })
}

/// Reject unsupported options with explicit errors instead of silently
/// mis-converting.
fn reject_unsupported(request: &ConvertRequest) -> Result<()> {
    if request.mode == ConversionMode::Reverse {
        bail!("--reverse (nydus->OCI) conversion is not yet supported by nydusify-rs (follow-up)");
    }
    // --source-archive/--target-archive read and write OCI layout tarballs; see
    // engine::oci_archive. Multi-platform is registry-only: an archive holds one
    // image, so there is no index to assemble into.
    if request.target_archive.is_some()
        && (request.all_platforms || request.platforms.contains(','))
    {
        bail!(
            "--target-archive writes a single image, so it cannot be combined with \
             --all-platforms or a multi-platform --platform list"
        );
    }
    if let Some(kind) = request.source_backend_type.as_deref()
        && kind != "registry"
    {
        bail!("--source-backend-type {kind} is not yet supported; only `registry` sources work");
    }
    let target_backend = request.driver.backend_type.as_str();
    if !target_backend.is_empty() && target_backend != "registry" {
        bail!(
            "--backend-type {target_backend} is not yet supported by nydusify-rs; only `registry` (default) is implemented (follow-up)"
        );
    }

    // Flags parsed by the CLI but not yet honored by the converter. Reject
    // them rather than silently dropping them and producing an image that
    // does not match the requested flags.
    let d = &request.driver;
    if !d.chunk_dict_ref.is_empty() {
        bail!("--chunk-dict is not yet supported by nydusify-rs (follow-up)");
    }
    if !d.cache_ref.is_empty() {
        bail!("--build-cache is not yet supported by nydusify-rs (follow-up)");
    }
    if d.backend_force_push {
        bail!("--backend-force-push is not yet supported by nydusify-rs (follow-up)");
    }
    if d.fs_align_chunk {
        bail!(
            "--fs-align-chunk/--backend-aligned-chunk is not yet supported by nydusify-rs (follow-up)"
        );
    }
    // Non-default build-tuning knobs are not plumbed into the nydus-image
    // invocation yet; only their defaults are safe to accept silently.
    if d.fs_chunk_size != "0x100000" {
        bail!(
            "--fs-chunk-size {} is not yet supported by nydusify-rs; only the default 0x100000 is used (follow-up)",
            d.fs_chunk_size
        );
    }
    if d.batch_size != "0" {
        bail!(
            "--batch-size {} is not yet supported by nydusify-rs (follow-up)",
            d.batch_size
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pull
// ---------------------------------------------------------------------------

/// Build a referrer `subject` descriptor for a resolved per-platform (or
/// single-arch) manifest — the digest `nydusify check` and the snapshotter
/// resolve the referrer against.
fn subject_descriptor(digest: String, size: u64, docker2oci: bool) -> Descriptor {
    Descriptor {
        media_type: manifest_media_type(docker2oci).to_string(),
        digest,
        size,
        ..Descriptor::default()
    }
}

/// Build a [`PulledSource`] from a local OCI layout tarball.
///
/// The archive already holds every layer, so nothing is downloaded; the layers
/// are used from the unpacked layout in place.
fn pull_source_from_archive(
    request: &ConvertRequest,
    archive: &Path,
    platform: &str,
    workspace: &Path,
) -> Result<PulledSource> {
    let unpacked = workspace.join("source-layout");
    let imported = oci_archive::import(archive, &unpacked)
        .with_context(|| format!("import --source-archive {}", archive.display()))?;
    let manifest = &imported.manifest;
    if manifest.layers.is_empty() {
        bail!(
            "--source-archive {} holds an image with no layers",
            archive.display()
        );
    }
    validate_layer_media_types(manifest)?;

    let (os, arch, variant) = crate::engine::oci::parse_platform(platform)?;
    let plat = registry_client::types::Platform {
        architecture: arch,
        os,
        variant,
        ..Default::default()
    };
    let referrer_subject = subject_descriptor(
        imported.descriptor.digest.clone(),
        imported.manifest_bytes.len() as u64,
        request.driver.docker2oci,
    );
    let config_bytes = std::fs::read(imported.blob_path(&manifest.config.digest)?)
        .context("read image config from the source archive")?;

    let mut layers = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        layers.push(PulledLayer {
            digest: layer.digest.clone(),
            path: imported.blob_path(&layer.digest)?,
        });
    }

    Ok(PulledSource {
        referrer_subject: Some(referrer_subject),
        platform: plat,
        source_size: manifest.layers.iter().map(|l| l.size).sum(),
        manifest_bytes: imported.manifest_bytes.clone(),
        source_index_entries: None,
        config_bytes,
        layers,
    })
}

/// Walk `--source` in stacking order, producing the merge inputs and the image whose
/// config the result inherits.
///
/// The anchor is the *uppermost* image source, matching the intuition that what you stack
/// last is what the image is: its config (entrypoint, env, architecture) is the one a
/// runtime sees, and its repo is where reused blobs are mounted from. `plan()` guarantees
/// at least one image source exists.
///
/// Every image source is pulled with the same client, so the source-side flags
/// (`--source-insecure`, `--source-plain-http`, credentials) apply to all of them; sources
/// spread across registries with differing settings are not supported.
async fn gather_sources(
    request: &ConvertRequest,
    client: Option<&RegistryClient>,
    anchor_ref: Option<&ImageReference>,
    platform: &str,
    workspace: &Path,
) -> Result<(PulledSource, Vec<BuildInput>)> {
    let mut inputs = Vec::new();
    let mut anchor: Option<PulledSource> = None;

    for spec in &request.sources {
        match spec {
            SourceSpec::Image(reference) => {
                let (Some(client), Some(anchor_ref)) = (client, anchor_ref) else {
                    // Unreachable: a source list holding an image is exactly what makes the
                    // caller build a client, so this cannot be reached without those two
                    // falling out of step.
                    bail!(
                        "--source {reference} is an image reference but no source registry \
                         client was built for it"
                    );
                };
                // The anchor is already parsed and validated by the caller; re-parsing it
                // would duplicate the error handling for no benefit.
                let image_ref = if request.source.as_deref() == Some(reference.as_str()) {
                    anchor_ref.clone()
                } else {
                    ImageReference::parse(reference)
                        .with_context(|| format!("parse --source {reference}"))?
                };
                let pulled = pull_source(request, client, &image_ref, platform, workspace).await?;
                inputs.extend(pulled.layers.iter().cloned().map(BuildInput::Layer));
                anchor = Some(pulled);
            }
            SourceSpec::Directory(dir) => {
                if !dir.is_dir() {
                    bail!(
                        "--source {} is not a directory (it was one when the conversion was planned)",
                        dir.display()
                    );
                }
                inputs.push(BuildInput::Directory(dir.clone()));
            }
        }
    }

    // With no image among the sources there is nothing to inherit a config from, so synthesise
    // a minimal one. Everything downstream treats it exactly like a pulled config: the
    // diff_ids are rewritten to match the built layers either way.
    let anchor = match anchor {
        Some(pulled) => pulled,
        None => {
            let (os, architecture, variant) = crate::engine::oci::parse_platform(platform)?;
            PulledSource {
                referrer_subject: None,
                platform: registry_client::types::Platform {
                    architecture: architecture.clone(),
                    os: os.clone(),
                    variant: variant.clone(),
                    ..Default::default()
                },
                source_size: 0,
                config_bytes: synthesize_image_config(&os, &architecture, variant.as_deref())?,
                manifest_bytes: Vec::new(),
                source_index_entries: None,
                layers: Vec::new(),
            }
        }
    };
    Ok((anchor, inputs))
}

async fn pull_source(
    request: &ConvertRequest,
    client: &RegistryClient,
    source_ref: &ImageReference,
    platform: &str,
    workspace: &Path,
) -> Result<PulledSource> {
    let repo = &source_ref.repo;
    let fetched = client
        .get_manifest(repo, source_ref.manifest_reference())
        .await
        .with_context(|| format!("fetch source manifest {source_ref}"))?;

    // Resolve an index/manifest-list down to this platform's manifest, and
    // capture the platform descriptor for the index entry.
    let (image_bytes, image_digest, plat, index_entries) =
        if is_index(fetched.content_type.as_deref(), &fetched.bytes) {
            let index: Index =
                serde_json::from_slice(&fetched.bytes).context("parse source image index")?;
            let entries = index.manifests.clone();
            let selected = select_platform(&index, platform)?;
            let plat = selected.platform.clone().unwrap_or_default();
            let img = client
                .get_manifest(repo, &selected.digest)
                .await
                .with_context(|| format!("fetch platform manifest {}", selected.digest))?;
            (img.bytes, img.digest, plat, Some(entries))
        } else {
            // Single-arch source: honor the requested platform selector for the
            // index entry's platform field (a single-arch image carries no
            // platform of its own in the manifest).
            let (os, arch, variant) = crate::engine::oci::parse_platform(platform)?;
            let plat = registry_client::types::Platform {
                architecture: arch,
                os,
                variant,
                ..Default::default()
            };
            (fetched.bytes, fetched.digest, plat, None)
        };

    // The referrer subject and fallback tag resolve against THIS manifest.
    let referrer_subject = subject_descriptor(
        image_digest.clone(),
        image_bytes.len() as u64,
        request.driver.docker2oci,
    );

    let manifest: Manifest =
        serde_json::from_slice(&image_bytes).context("parse source image manifest")?;
    if manifest.layers.is_empty() {
        bail!("source image manifest {image_digest} has no layers");
    }
    validate_layer_media_types(&manifest)?;
    let source_size: u64 = manifest.layers.iter().map(|l| l.size).sum();

    let config_bytes = client
        .get_blob(repo, &manifest.config.digest)
        .await
        .with_context(|| format!("fetch image config {}", manifest.config.digest))?;

    let layers_dir = workspace.join("layers");
    std::fs::create_dir_all(&layers_dir)
        .with_context(|| format!("create layers dir {}", layers_dir.display()))?;
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        let path = layers_dir.join(blob_hex(&layer.digest));
        client
            .get_blob_to_file(repo, &layer.digest, &path)
            .await
            .with_context(|| format!("download layer {}", layer.digest))?;
        layers.push(PulledLayer {
            digest: layer.digest.clone(),
            path,
        });
    }

    Ok(PulledSource {
        referrer_subject: Some(referrer_subject),
        platform: plat,
        source_size,
        manifest_bytes: image_bytes,
        source_index_entries: index_entries,
        config_bytes,
        layers,
    })
}

/// Reject source layers `nydus-image create --type targz-*` cannot ingest.
///
/// The converter feeds each layer to `nydus-image` as a gzip'd (or plain) tar
/// stream. zstd-compressed layers, foreign/non-distributable layers, and any
/// non-tar layer media type would silently mis-convert or fail deep in the
/// subprocess; reject them up front with a clear message.
fn validate_layer_media_types(manifest: &Manifest) -> Result<()> {
    for layer in &manifest.layers {
        let mt = layer.media_type.as_str();
        let lower = mt.to_ascii_lowercase();
        if lower.contains("zstd") {
            bail!(
                "source layer {} has media type {mt}: zstd-compressed layers are not supported by nydusify-rs (only gzip/uncompressed tar layers)",
                layer.digest
            );
        }
        if lower.contains("foreign") || lower.contains("nondistributable") {
            bail!(
                "source layer {} has media type {mt}: foreign/non-distributable layers cannot be converted",
                layer.digest
            );
        }
        // Must be a tar-based layer (…tar or …tar+gzip / …tar.gzip).
        let is_tar = lower.contains(".tar") || lower.ends_with("tar+gzip");
        if !is_tar {
            bail!(
                "source layer {} has unsupported media type {mt}: expected a tar or gzip'd-tar image layer",
                layer.digest
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Build (nydus-image subprocess)
// ---------------------------------------------------------------------------

fn build_artifact(
    request: &ConvertRequest,
    inputs: &[BuildInput],
    workspace: &Path,
) -> Result<ConversionOutput> {
    let nydus_image = request.driver.builder.as_path();
    let fs_version = request.driver.fs_version.as_str();
    let convert_root = workspace.join("convert");
    std::fs::create_dir_all(&convert_root)
        .with_context(|| format!("create conversion workspace {}", convert_root.display()))?;

    let mut layer_bootstraps = Vec::with_capacity(inputs.len());
    let mut new_blobs = Vec::new();
    let mut original_blob_ids = Vec::with_capacity(inputs.len());

    for (i, input) in inputs.iter().enumerate() {
        let out_dir = convert_root.join(format!("l{i}-{}", input.slug()));
        fresh_dir(&out_dir)?;
        let bootstrap_i = out_dir.join("bootstrap");
        let args = match input {
            BuildInput::Layer(layer) if request.driver.oci_ref => {
                targz_ref_args(&layer.path, &bootstrap_i, &out_dir, fs_version)
            }
            BuildInput::Layer(layer) => targz_rafs_args(
                &layer.path,
                &bootstrap_i,
                &out_dir,
                fs_version,
                &request.driver.compressor,
            ),
            // A directory is built straight into a nydus layer. `--oci-ref` is
            // rejected for multi-source conversions precisely because there is no
            // original gzip stream here for zran to index into.
            BuildInput::Directory(dir) => dir_rafs_args(
                dir,
                &bootstrap_i,
                &out_dir,
                fs_version,
                &request.driver.compressor,
                &excludes_for_directory(dir, &request.append_in_bootstrap),
            ),
        };
        run_nydus_image(
            nydus_image,
            &args,
            &format!("create from {}", input.describe()),
        )?;
        // A layer with no file content -- only directories, or only whiteouts --
        // yields a bootstrap but no data blob, and that is perfectly ordinary
        // (postgres:latest has a 116-byte layer holding one empty directory).
        // Only the blob is optional: `merge` indexes --original-blob-ids by layer
        // and requires exactly one entry per source bootstrap, so those two stay
        // one-per-layer regardless.
        let blob = single_output(&out_dir, Some(&bootstrap_i))
            .context("locating per-layer nydus data blob")?;

        // Without --original-blob-ids, `merge` takes each source's blob id from its
        // bootstrap FILE NAME (BlobInfo::get_blob_id_from_meta_path) and dedupes the
        // blob table by that id. Naming every layer's bootstrap "bootstrap" therefore
        // collapses all of them onto ONE blob-table entry with the literal id
        // "bootstrap", and every layer's chunks get remapped onto it -- a merged image
        // referencing chunks its single blob does not contain, which `nydus-image
        // check` rejects. Name each bootstrap after its own blob instead. (The
        // --oci-ref path supplies the ids explicitly and is unaffected, but there is
        // no reason for the two to disagree.)
        let bootstrap_i = match layer_bootstrap_path(&out_dir, blob.as_deref())? {
            Some(named) => {
                std::fs::rename(&bootstrap_i, &named).with_context(|| {
                    format!(
                        "rename layer bootstrap {} -> {}",
                        bootstrap_i.display(),
                        named.display()
                    )
                })?;
                named
            }
            None => bootstrap_i,
        };

        layer_bootstraps.push(bootstrap_i);
        if let Some(blob) = blob {
            new_blobs.push(blob);
        }
        // Only consumed on the `--oci-ref` path, which never sees a directory input.
        if let BuildInput::Layer(layer) = input {
            original_blob_ids.push(blob_hex(&layer.digest).to_string());
        }
    }

    // Merge the per-layer bootstraps (lower->upper) into one.
    let bootstrap = workspace.join("bootstrap");
    let margs = if request.driver.oci_ref {
        merge_args(&bootstrap, Some(&original_blob_ids), &layer_bootstraps)
    } else {
        merge_args(&bootstrap, None, &layer_bootstraps)
    };
    run_nydus_image(nydus_image, &margs, "merge")?;

    let reused_layers = if request.driver.oci_ref {
        inputs
            .iter()
            .filter_map(|i| match i {
                BuildInput::Layer(l) => Some(l.clone()),
                BuildInput::Directory(_) => None,
            })
            .collect()
    } else {
        Vec::new()
    };

    // Optional prefetch optimization.
    let prefetch_files = parse_prefetch_files(&request.driver.prefetch_patterns);
    let pattern_file = request.driver.prefetch_pattern_file.as_deref();
    if !prefetch_files.is_empty() || pattern_file.is_some() {
        match run_optimize(
            nydus_image,
            workspace,
            &bootstrap,
            &new_blobs,
            &reused_layers,
            &prefetch_files,
            pattern_file,
        ) {
            Ok(prefetch_blob) => new_blobs.push(prefetch_blob),
            Err(e) => warn!(error = %e, "prefetch optimize failed; pushing un-optimized bootstrap"),
        }
    }

    Ok(ConversionOutput {
        bootstrap,
        new_blobs,
        reused_layers,
    })
}

/// `nydus-image create --type targz-ref` (zran) args.
fn targz_ref_args(
    layer: &Path,
    bootstrap_out: &Path,
    blob_out_dir: &Path,
    fs_version: &str,
) -> Vec<OsString> {
    vec![
        "create".into(),
        "--type".into(),
        "targz-ref".into(),
        "--fs-version".into(),
        fs_version.into(),
        "-B".into(),
        bootstrap_out.into(),
        "-D".into(),
        blob_out_dir.into(),
        layer.into(),
    ]
}

/// `nydus-image create --type dir-rafs` args for a local directory source.
///
/// `dir-rafs` walks the directory itself rather than a tar stream, so the directory is
/// the image content as-is: no whiteouts, no layer semantics, just files.
fn dir_rafs_args(
    dir: &Path,
    bootstrap_out: &Path,
    blob_out_dir: &Path,
    fs_version: &str,
    compressor: &str,
    excludes: &[PathBuf],
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "create".into(),
        "--type".into(),
        "dir-rafs".into(),
        "--fs-version".into(),
        fs_version.into(),
        "--compressor".into(),
        compressor.into(),
        "-B".into(),
        bootstrap_out.into(),
        "-D".into(),
        blob_out_dir.into(),
    ];
    for exclude in excludes {
        args.push("--exclude".into());
        args.push(exclude.into());
    }
    // Positional, so it stays last.
    args.push(dir.into());
    args
}

/// In-image paths to exclude from `dir`'s build: the `--append-in-bootstrap` files that live
/// inside it.
///
/// Those files travel in the bootstrap layer instead, so building them into this source's data
/// blob as well would put two copies in the image with nothing keeping them in step.
fn excludes_for_directory(dir: &Path, append_in_bootstrap: &[PathBuf]) -> Vec<PathBuf> {
    append_in_bootstrap
        .iter()
        .filter_map(|file| {
            file.strip_prefix(dir)
                .ok()
                .map(|relative| Path::new("/").join(relative))
        })
        .collect()
}

/// `nydus-image create --type targz-rafs` (standard, new data blob) args.
fn targz_rafs_args(
    layer: &Path,
    bootstrap_out: &Path,
    blob_out_dir: &Path,
    fs_version: &str,
    compressor: &str,
) -> Vec<OsString> {
    vec![
        "create".into(),
        "--type".into(),
        "targz-rafs".into(),
        "--fs-version".into(),
        fs_version.into(),
        "--compressor".into(),
        compressor.into(),
        "-B".into(),
        bootstrap_out.into(),
        "-D".into(),
        blob_out_dir.into(),
        layer.into(),
    ]
}

/// `nydus-image merge` args. `original_blob_ids` is supplied only for the
/// `--oci-ref` path (where the data blobs are the external gzip layers).
fn merge_args(
    bootstrap_out: &Path,
    original_blob_ids: Option<&[String]>,
    layer_bootstraps: &[PathBuf],
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["merge".into(), "-B".into(), bootstrap_out.into()];
    if let Some(ids) = original_blob_ids {
        args.push("--original-blob-ids".into());
        args.push(ids.join(",").into());
    }
    for b in layer_bootstraps {
        args.push(b.into());
    }
    args
}

/// Bake prefetch hints into the bootstrap via `nydus-image optimize`. Returns
/// the path of the new packed prefetch blob (its file name is the blob id).
///
/// `pattern_file`, when present, is a caller-supplied access-pattern document that is used
/// as-is instead of one synthesised from `prefetch_files`. Copying it rather than parsing and
/// re-emitting it keeps whatever the recorder wrote — per-file byte `ranges` above all, which
/// the synthesised form has no way to express.
fn run_optimize(
    nydus_image: &Path,
    workspace: &Path,
    bootstrap: &Path,
    new_blobs: &[PathBuf],
    reused_layers: &[PulledLayer],
    prefetch_files: &[String],
    pattern_file: Option<&Path>,
) -> Result<PathBuf> {
    // optimize needs every blob the bootstrap references in one --blob-dir.
    let blob_dir = workspace.join("optimize-blobs");
    fresh_dir(&blob_dir)?;
    for layer in reused_layers {
        link_or_copy(&layer.path, &blob_dir.join(blob_hex(&layer.digest)))?;
    }
    for blob in new_blobs {
        let name = blob
            .file_name()
            .context("nydus data blob has no file name")?;
        link_or_copy(blob, &blob_dir.join(name))?;
    }

    let prefetch_json = workspace.join("prefetch.json");
    match pattern_file {
        Some(src) => {
            std::fs::copy(src, &prefetch_json).with_context(|| {
                format!(
                    "stage access-pattern file {} as {}",
                    src.display(),
                    prefetch_json.display()
                )
            })?;
        }
        None => {
            let json = serde_json::json!({
                "version": "v1",
                "files": prefetch_files
                    .iter()
                    .map(|p| serde_json::json!({ "path": p, "ranges": null }))
                    .collect::<Vec<_>>(),
            });
            std::fs::write(&prefetch_json, serde_json::to_vec(&json)?)
                .with_context(|| format!("write {}", prefetch_json.display()))?;
        }
    }

    let out_blob_dir = workspace.join("optimize-out");
    fresh_dir(&out_blob_dir)?;
    let optimized = workspace.join("bootstrap.optimized");
    let args: Vec<OsString> = vec![
        "optimize".into(),
        "--bootstrap".into(),
        bootstrap.into(),
        "--prefetch-files".into(),
        prefetch_json.as_path().into(),
        "--blob-dir".into(),
        blob_dir.as_path().into(),
        "--output-bootstrap".into(),
        optimized.as_path().into(),
        "--output-blob-dir".into(),
        out_blob_dir.as_path().into(),
    ];
    run_nydus_image(nydus_image, &args, "optimize")?;

    // Validate the prefetch blob BEFORE swapping bootstraps: if the rename
    // happened first, a validation failure would leave the optimized
    // bootstrap (which references the un-pushed prefetch blob) in place while
    // the caller logs "pushing un-optimized bootstrap" — publishing a
    // bootstrap whose prefetch blob never reaches the registry.
    let prefetch_blob = single_output(&out_blob_dir, None)
        .context("locating optimize prefetch blob")?
        .ok_or_else(|| {
            anyhow!(
                "nydus-image optimize produced no prefetch blob in {}",
                out_blob_dir.display()
            )
        })?;
    std::fs::rename(&optimized, bootstrap)
        .context("replace merged bootstrap with optimized one")?;
    Ok(prefetch_blob)
}

/// Parse `prefetch_patterns` into concrete in-image file paths. The root
/// pattern `/` (the default) and empty entries are dropped: `optimize
/// --prefetch-files` wants a concrete file list, not a whole-tree glob, so an
/// all-root request means "no explicit prefetch" here and the optimize step is
/// skipped.
fn parse_prefetch_files(patterns: &str) -> Vec<String> {
    patterns
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != "/")
        .map(String::from)
        .collect()
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

/// `artifactType` current nydus parsers use to spot the nydus manifest inside a dual index
/// (`contrib/nydusify/pkg/parser`), plus the legacy `os.features` marker parsers before
/// v2.3.5 keyed on. Both are set on the nydus entry.
const NYDUS_MANIFEST_ARTIFACT_TYPE: &str = "application/vnd.nydus.image.manifest.v1+json";
const NYDUS_OS_FEATURE: &str = "nydus.remoteimage.v1";

/// Publish the target tag as an OCI index carrying the untouched source OCI manifest and the
/// just-pushed nydus manifest.
///
/// Layout follows the Go ecosystem's `merge_manifest` (goharbor/acceleration-service
/// `makeManifestIndex`): OCI entries first, nydus entries after, the nydus descriptor marked
/// via `artifactType`. Two deliberate divergences. The OCI manifest is **not** modified --
/// accel-service prepends an empty layer to defeat Harbor-side layer reuse, but a
/// byte-identical manifest is the whole point here: existing digest pins keep resolving and a
/// scan of the OCI half is a scan of the original image. And the legacy `os.features` marker
/// is kept alongside `artifactType`, because strict platform matchers treat an unknown
/// required feature as "no match" and skip the nydus half -- exactly what a scanner should do.
///
/// Ordering is load-bearing: consumers that ignore both markers and take the first platform
/// match (plain containerd, docker) must land on the standard image, never the nydus one.
#[allow(clippy::too_many_arguments)]
async fn attach_oci_manifest_and_push_index(
    target_client: &RegistryClient,
    target_ref: &ImageReference,
    source_ref: Option<&ImageReference>,
    same_registry: bool,
    source: &PulledSource,
    nydus_manifest: &Descriptor,
    retry: &RetryPolicy,
) -> Result<()> {
    let source_ref = source_ref
        .context("--attach-oci-manifest requires an image --source (plan enforces this)")?;
    let repo = &target_ref.repo;
    let manifest: Manifest = serde_json::from_slice(&source.manifest_bytes)
        .context("re-parse the source manifest for --attach-oci-manifest")?;
    let oci_media_type = manifest
        .media_type
        .clone()
        .unwrap_or_else(|| registry_client::types::MEDIA_TYPE_OCI_MANIFEST.to_string());
    let oci_digest = registry_client::types::sha256_digest(&source.manifest_bytes);

    // The OCI half must be resolvable from the target repo. Converting in place -- source and
    // target being the same repo, the migration case -- everything is already there.
    let same_repo = same_registry && source_ref.repo == target_ref.repo;
    if !same_repo {
        for layer in &source.layers {
            if target_client.head_blob(repo, &layer.digest).await? {
                continue;
            }
            let mounted = same_registry
                && target_client
                    .mount_blob(repo, &layer.digest, &source_ref.repo)
                    .await
                    .unwrap_or(false);
            if !mounted {
                retry
                    .run("push source layer", || {
                        target_client.push_blob_file(repo, &layer.path)
                    })
                    .await
                    .with_context(|| format!("push source layer {}", layer.digest))?;
            }
        }
        if !target_client
            .head_blob(repo, &manifest.config.digest)
            .await?
        {
            retry
                .run("push source config", || {
                    target_client.push_blob_bytes(repo, &source.config_bytes)
                })
                .await
                .context("push the source image config")?;
        }
        retry
            .run("push source manifest", || {
                target_client.push_manifest(
                    repo,
                    &oci_digest,
                    &oci_media_type,
                    &source.manifest_bytes,
                )
            })
            .await
            .context("push the source manifest by digest")?;
    }

    let base_entries = match &source.source_index_entries {
        Some(entries) => {
            // Preserve every original entry; the other architectures' manifests already
            // live in this repo only in the same-repo case, and copying an arbitrary
            // index's whole tree is out of scope.
            if !same_repo {
                bail!(
                    "--attach-oci-manifest onto a multi-entry source index is only \
                     supported when source and target are the same repository; converting \
                     {source_ref} into {target_ref} would drop the entries not copied"
                );
            }
            entries.clone()
        }
        None => vec![Descriptor {
            media_type: oci_media_type,
            digest: oci_digest,
            size: source.manifest_bytes.len() as u64,
            platform: Some(source.platform.clone()),
            ..Descriptor::default()
        }],
    };
    let index_bytes = serde_json::to_vec(&dual_manifest_index(
        base_entries,
        nydus_manifest,
        &source.platform,
    ))
    .context("serialize the dual-manifest index")?;
    retry
        .run("push dual-manifest index", || {
            target_client.push_manifest(
                repo,
                target_ref.manifest_reference(),
                index_media_type(true),
                &index_bytes,
            )
        })
        .await
        .context("push the dual-manifest index")?;
    info!(
        target = %target_ref,
        "published dual-manifest index: OCI + nydus under one tag"
    );
    Ok(())
}

/// Does this index entry describe a nydus manifest?
///
/// Both markers are checked because they are written for different readers: current nydus
/// parsers key on `artifactType`, while `os.features` carries the legacy marker for older
/// parsers. An index assembled by another tool (or an older nydusify) may carry only one.
fn is_nydus_entry(entry: &Descriptor) -> bool {
    entry.artifact_type.as_deref() == Some(NYDUS_MANIFEST_ARTIFACT_TYPE)
        || entry.platform.as_ref().is_some_and(|p| {
            p.os_features
                .as_ref()
                .is_some_and(|f| f.iter().any(|feature| feature == NYDUS_OS_FEATURE))
        })
}

/// Same platform, ignoring `os.features` -- the nydus entry differs from its OCI sibling
/// exactly there, so comparing it would never match.
fn same_platform(
    a: &registry_client::types::Platform,
    b: &registry_client::types::Platform,
) -> bool {
    a.architecture == b.architecture
        && a.os == b.os
        && a.os_version == b.os_version
        && a.variant == b.variant
}

/// Assemble the dual-manifest index: the base entries first, the nydus manifest last,
/// marked by `artifactType` and the legacy `os.features`. Pure so the layout -- the part
/// consumers key on -- is testable.
///
/// Converting a tag that has already been converted REPLACES its nydus entry for this
/// platform rather than appending a second one. Without that, a re-conversion accumulates
/// stale nydus manifests: `--attach-oci-manifest` republishes the source index verbatim,
/// and when source == target that index already contains the previous run's nydus entry.
/// Observed in the wild on 2026-08-10 -- three tags re-converted from standard mode to
/// `--oci-ref` ended up advertising two nydus manifests each, the stale one still pointing
/// at now-unreferenced full RAFS blobs. Which of the two a consumer picks is undefined,
/// so this is a correctness bug, not just wasted storage.
///
/// Only entries for *this* platform are dropped: a multi-arch tag can legitimately carry
/// one nydus manifest per architecture, converted by separate runs.
fn dual_manifest_index(
    base_entries: Vec<Descriptor>,
    nydus_manifest: &Descriptor,
    platform: &registry_client::types::Platform,
) -> Index {
    let mut nydus_platform = platform.clone();
    nydus_platform.os_features = Some(vec![NYDUS_OS_FEATURE.to_string()]);
    let nydus_desc = Descriptor {
        artifact_type: Some(NYDUS_MANIFEST_ARTIFACT_TYPE.to_string()),
        platform: Some(nydus_platform),
        ..nydus_manifest.clone()
    };
    let mut manifests: Vec<Descriptor> = base_entries
        .into_iter()
        .filter(|entry| {
            let superseded = is_nydus_entry(entry)
                && entry
                    .platform
                    .as_ref()
                    .is_some_and(|p| same_platform(p, platform));
            if superseded {
                info!(
                    digest = %entry.digest,
                    "replacing the existing nydus manifest for this platform"
                );
            }
            !superseded
        })
        .collect();
    manifests.push(nydus_desc);
    assemble_index(true, manifests)
}

/// A pushed per-platform nydus manifest plus the total bytes of nydus content
/// it published (data blobs + bootstrap + config + manifest), for reporting.
struct PushedArtifact {
    manifest: Descriptor,
    target_size: u64,
}

#[allow(clippy::too_many_arguments)]
async fn push_artifact(
    request: &ConvertRequest,
    client: &RegistryClient,
    target_ref: &ImageReference,
    // `None` for a directory-only conversion, which has no source repo to mount blobs from --
    // and no reused layers to mount either, since `--oci-ref` is refused without an image.
    source_ref: Option<&ImageReference>,
    same_registry: bool,
    source: &PulledSource,
    output: &ConversionOutput,
    push_target: PushTarget,
    retry: &RetryPolicy,
) -> Result<PushedArtifact> {
    let repo = &target_ref.repo;
    let docker2oci = request.driver.docker2oci;

    let mut data_blobs = Vec::new();

    // Reused original layers (--oci-ref): mount on a same-registry target, else push.
    for layer in &output.reused_layers {
        let source_repo = source_ref.map(|r| &r.repo);
        let mounted = if same_registry && source_repo.is_some_and(|r| r != &target_ref.repo) {
            client
                .mount_blob(
                    repo,
                    &layer.digest,
                    source_repo.expect("checked just above"),
                )
                .await
                .unwrap_or(false)
        } else {
            // Same repo: the blob is already there. Cross-registry: must push.
            same_registry
        };
        if !mounted {
            retry
                .run("push reused layer", || {
                    client.push_blob_file(repo, &layer.path)
                })
                .await
                .with_context(|| format!("push reused layer {}", layer.digest))?;
        } else {
            debug!(%repo, digest = %layer.digest, "reused layer already present / mounted");
        }
        let size = file_len(&layer.path)?;
        data_blobs.push(data_blob_descriptor(layer.digest.clone(), size));
    }

    // Newly-created nydus data blobs.
    for blob in &output.new_blobs {
        let digest = retry
            .run("push nydus blob", || client.push_blob_file(repo, blob))
            .await
            .with_context(|| format!("push nydus blob {}", blob.display()))?;
        data_blobs.push(data_blob_descriptor(digest, file_len(blob)?));
    }

    // Bootstrap. Published as an ordinary gzip'd tar holding `image/image.boot`,
    // not as a raw blob under a bespoke media type: containerd has to be able to
    // unpack it with its normal tar+gzip path (no stream processor), and the
    // snapshotter reads the bootstrap out of the expanded snapshot.
    let boot_layer = bootstrap_layer::pack(&output.bootstrap, &request.append_in_bootstrap)?;
    let boot_digest = retry
        .run("push nydus bootstrap", || {
            client.push_blob_bytes(repo, &boot_layer.gzip_bytes)
        })
        .await
        .context("push nydus bootstrap")?;
    let bootstrap = bootstrap_descriptor(
        boot_digest,
        boot_layer.diff_id.clone(),
        boot_layer.gzip_bytes.len() as u64,
    );

    // Rebuild the image config so `rootfs.diff_ids` has exactly one entry per
    // pushed manifest layer (data blobs first, bootstrap last) — otherwise
    // containerd rejects the image with "mismatched image rootfs and manifest
    // layers". These are DIFF ids, i.e. the digest of each layer *uncompressed*:
    // for a nydus data blob that is the blob digest, but for the gzip'd bootstrap
    // it is the tar digest, and containerd recomputes it while unpacking.
    let layer_diff_ids: Vec<String> = data_blobs
        .iter()
        .map(|d| d.digest.clone())
        .chain(std::iter::once(boot_layer.diff_id))
        .collect();
    let config_bytes = rebuild_image_config(&source.config_bytes, &layer_diff_ids)
        .context("rewrite image config diff_ids/history for nydus layer set")?;
    let config_digest = retry
        .run("push image config", || {
            client.push_blob_bytes(repo, &config_bytes)
        })
        .await
        .context("push rewritten image config")?;
    let config = Descriptor {
        media_type: config_media_type(docker2oci).to_string(),
        digest: config_digest,
        size: config_bytes.len() as u64,
        ..Descriptor::default()
    };

    // Accumulate published nydus content size before consuming data_blobs.
    let content_size: u64 =
        data_blobs.iter().map(|d| d.size).sum::<u64>() + bootstrap.size + config.size;

    // Manifest.
    let manifest = assemble_manifest(docker2oci, config, data_blobs, bootstrap);
    let manifest_bytes = serde_json::to_vec(&manifest).context("serialize nydus manifest")?;
    let media_type = manifest_media_type(docker2oci);
    // Single-platform: publish at the target tag. A leaf of a multi-arch index:
    // publish by its own digest (the index references it by digest; only the
    // index carries the tag).
    let manifest_digest = registry_client::types::sha256_digest(&manifest_bytes);
    let reference: &str = match push_target {
        PushTarget::Tag => target_ref.manifest_reference(),
        PushTarget::ByDigest => &manifest_digest,
    };
    let pushed_digest = retry
        .run("push nydus manifest", || {
            client.push_manifest(repo, reference, media_type, &manifest_bytes)
        })
        .await
        .with_context(|| format!("push nydus manifest to {target_ref}"))?;

    Ok(PushedArtifact {
        manifest: Descriptor {
            media_type: media_type.to_string(),
            digest: pushed_digest,
            size: manifest_bytes.len() as u64,
            ..Descriptor::default()
        },
        target_size: content_size + manifest_bytes.len() as u64,
    })
}

/// Write the converted image to a local OCI layout tarball instead of pushing.
///
/// Everything the archive needs is already on disk or in memory after the build
/// -- reused gzip layers, new nydus blobs, the packed bootstrap and the rewritten
/// config -- so no registry is contacted at all.
fn export_artifact(
    request: &ConvertRequest,
    archive: &Path,
    source: &PulledSource,
    output: &ConversionOutput,
    target_ref: &str,
    workspace: &Path,
) -> Result<PushedArtifact> {
    let docker2oci = request.driver.docker2oci;
    let staging = workspace.join("archive-blobs");
    std::fs::create_dir_all(&staging)
        .with_context(|| format!("create archive staging {}", staging.display()))?;

    let mut data_blobs = Vec::new();
    let mut archive_blobs = Vec::new();
    for path in output
        .reused_layers
        .iter()
        .map(|l| &l.path)
        .chain(output.new_blobs.iter())
    {
        let size = file_len(path)?;
        let digest = registry_client::types::sha256_digest(
            &std::fs::read(path).with_context(|| format!("read blob {}", path.display()))?,
        );
        data_blobs.push(data_blob_descriptor(digest.clone(), size));
        archive_blobs.push(ArchiveBlob {
            digest,
            size,
            path: path.clone(),
        });
    }

    let boot_layer = bootstrap_layer::pack(&output.bootstrap, &request.append_in_bootstrap)?;
    let boot_path = staging.join("bootstrap.tar.gz");
    std::fs::write(&boot_path, &boot_layer.gzip_bytes)
        .with_context(|| format!("stage bootstrap layer {}", boot_path.display()))?;
    let bootstrap = bootstrap_descriptor(
        boot_layer.digest.clone(),
        boot_layer.diff_id.clone(),
        boot_layer.gzip_bytes.len() as u64,
    );
    archive_blobs.push(ArchiveBlob {
        digest: boot_layer.digest.clone(),
        size: boot_layer.gzip_bytes.len() as u64,
        path: boot_path,
    });

    let layer_diff_ids: Vec<String> = data_blobs
        .iter()
        .map(|d| d.digest.clone())
        .chain(std::iter::once(boot_layer.diff_id))
        .collect();
    let config_bytes = rebuild_image_config(&source.config_bytes, &layer_diff_ids)
        .context("rewrite image config for the archived nydus image")?;
    let config_digest = registry_client::types::sha256_digest(&config_bytes);
    let config_path = staging.join("config.json");
    std::fs::write(&config_path, &config_bytes)
        .with_context(|| format!("stage image config {}", config_path.display()))?;
    let config = Descriptor {
        media_type: config_media_type(docker2oci).to_string(),
        digest: config_digest.clone(),
        size: config_bytes.len() as u64,
        ..Descriptor::default()
    };
    archive_blobs.push(ArchiveBlob {
        digest: config_digest,
        size: config_bytes.len() as u64,
        path: config_path,
    });

    let content_size: u64 =
        data_blobs.iter().map(|d| d.size).sum::<u64>() + bootstrap.size + config.size;
    let manifest = assemble_manifest(docker2oci, config, data_blobs, bootstrap);
    let manifest_bytes = serde_json::to_vec(&manifest).context("serialize nydus manifest")?;
    let media_type = manifest_media_type(docker2oci);

    oci_archive::export(
        archive,
        &manifest_bytes,
        media_type,
        target_ref,
        &archive_blobs,
    )
    .with_context(|| format!("write --target-archive {}", archive.display()))?;

    info!(
        archive = %archive.display(),
        layers = manifest.layers.len(),
        "wrote nydus image to OCI archive"
    );

    Ok(PushedArtifact {
        manifest: Descriptor {
            media_type: media_type.to_string(),
            digest: registry_client::types::sha256_digest(&manifest_bytes),
            size: manifest_bytes.len() as u64,
            ..Descriptor::default()
        },
        target_size: content_size + manifest_bytes.len() as u64,
    })
}

/// Serialize the convert summary to `--output-json`. The original fields
/// (`target`, `manifest_digest`, `manifest_size`, `data_blobs`) describe the
/// primary manifest (the sole platform, or the first of a merged set) and are
/// kept for compatibility; the Go-parity metric fields are a superset:
/// `SourceImageSize` / `TargetImageSize` (byte totals across converted
/// platforms) and `ConversionElapsed` (seconds, filled by the caller). A
/// `platforms` array carries the per-platform breakdown.
fn platform_string(p: &registry_client::types::Platform) -> String {
    match &p.variant {
        Some(v) => format!("{}/{}/{}", p.os, p.architecture, v),
        None => format!("{}/{}", p.os, p.architecture),
    }
}

fn write_output_json(
    path: &Path,
    target_ref: &ImageReference,
    outcomes: &[PlatformOutcome],
    elapsed_secs: f64,
) -> Result<()> {
    let primary = outcomes
        .first()
        .expect("write_output_json requires at least one converted platform");
    let source_total: u64 = outcomes.iter().map(|o| o.source_size).sum();
    let target_total: u64 = outcomes.iter().map(|o| o.target_size).sum();
    let per_platform: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|o| {
            serde_json::json!({
                "platform": platform_string(&o.platform),
                "manifest_digest": o.manifest.digest,
                "manifest_size": o.manifest.size,
                "data_blobs": o.data_blob_count,
                "SourceImageSize": o.source_size,
                "TargetImageSize": o.target_size,
            })
        })
        .collect();
    let summary = serde_json::json!({
        "target": target_ref.to_string(),
        "manifest_digest": primary.manifest.digest,
        "manifest_size": primary.manifest.size,
        "data_blobs": primary.data_blob_count,
        "SourceImageSize": source_total,
        "TargetImageSize": target_total,
        "ConversionElapsed": format!("{elapsed_secs:.3}s"),
        "platforms": per_platform,
    });
    // Callers routinely derive this path from an image name, and a namespaced name
    // (`hashicorp/vault`) puts a directory component in it that nobody created.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create --output-json directory {}", parent.display()))?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(&summary)?)
        .with_context(|| format!("write --output-json {}", path.display()))
}

// ---------------------------------------------------------------------------
// Subprocess + fs helpers (mirrors local_accel.rs)
// ---------------------------------------------------------------------------

fn file_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len())
}

/// Run `nydus-image <args>`, capturing stderr on failure.
fn run_nydus_image(nydus_image: &Path, args: &[OsString], what: &str) -> Result<()> {
    let output = Command::new(nydus_image)
        .args(args)
        .output()
        .with_context(|| format!("spawn `{}` for {what}", nydus_image.display()))?;
    if !output.status.success() {
        bail!(
            "nydus-image {what} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// (Re)create `dir` empty so each `nydus-image` invocation owns a private dir
/// and "exactly one output file" is a structural guarantee.
fn fresh_dir(dir: &Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("clearing stale dir {}", dir.display())),
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating dir {}", dir.display()))
}

/// Where a layer's bootstrap must live so that `merge` derives the right blob id
/// for it, or `None` when the current name is already fine.
///
/// Without `--original-blob-ids`, `merge` takes each source's blob id from its
/// bootstrap file name (`BlobInfo::get_blob_id_from_meta_path`, which strips every
/// extension) and dedupes the blob table by that id. So the bootstrap has to be
/// named after its own blob; leaving every layer's called "bootstrap" collapses the
/// whole table onto one entry with the literal id "bootstrap".
///
/// A blob-less layer contributes no blob-table entry, so merge never derives an id
/// from its name and it can stay where it is.
fn layer_bootstrap_path(out_dir: &Path, blob: Option<&Path>) -> Result<Option<PathBuf>> {
    let Some(blob) = blob else {
        return Ok(None);
    };
    let blob_id = blob
        .file_name()
        .context("per-layer nydus data blob has no file name")?
        .to_str()
        .context("per-layer nydus data blob has a non-UTF-8 file name")?;
    // The blob itself already owns `<out_dir>/<blob_id>`; the suffix keeps the
    // bootstrap a distinct file, and get_blob_id_from_meta_path strips it back off.
    Ok(Some(out_dir.join(format!("{blob_id}.boot"))))
}

/// Return the single file in `dir` other than `exclude`, or `None` when the dir
/// holds nothing else. More than one candidate in a freshly-wiped private dir
/// means `nydus-image` produced unexpected output — a real bug, surfaced.
///
/// Sidecars of `exclude` — a sibling named `<exclude>.<something>` — are excluded too.
/// `--type dir-rafs` writes a `bootstrap.external` next to the bootstrap where
/// `targz-rafs` writes nothing of the kind, and without this a directory source would
/// always fail here with "produced unexpected output" rather than yielding its blob.
fn single_output(dir: &Path, exclude: Option<&Path>) -> Result<Option<PathBuf>> {
    let exclude_name = exclude.and_then(Path::file_name);
    let sidecar_prefix = exclude_name
        .and_then(|n| n.to_str())
        .map(|n| format!("{n}."));
    let mut found = None;
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("reading output dir {}", dir.display()))?
    {
        let entry = entry?;
        if !entry.path().is_file() || Some(entry.file_name().as_os_str()) == exclude_name {
            continue;
        }
        if let (Some(prefix), Some(name)) = (&sidecar_prefix, entry.file_name().to_str())
            && name.starts_with(prefix.as_str())
        {
            continue;
        }
        if found.is_some() {
            bail!(
                "nydus-image wrote more than one output file into {} (unexpected)",
                dir.display()
            );
        }
        found = Some(entry.path());
    }
    Ok(found)
}

/// Symlink `target` into `link` (unix), falling back to a copy elsewhere.
fn link_or_copy(target: &Path, link: &Path) -> Result<()> {
    let _ = std::fs::remove_file(link);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
            .with_context(|| format!("symlink {} -> {}", link.display(), target.display()))
    }
    #[cfg(not(unix))]
    {
        std::fs::copy(target, link)
            .map(|_| ())
            .with_context(|| format!("copy {} -> {}", target.display(), link.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn oci_ref_create_args() {
        let args = targz_ref_args(
            Path::new("/cs/layer.tgz"),
            Path::new("/w/l0/bootstrap"),
            Path::new("/w/l0"),
            "6",
        );
        let s = to_strings(&args);
        assert_eq!(s[0], "create");
        assert!(s.windows(2).any(|w| w == ["--type", "targz-ref"]));
        assert!(s.windows(2).any(|w| w == ["--fs-version", "6"]));
        assert_eq!(s.last().unwrap(), "/cs/layer.tgz");
        // zran path never re-compresses, so no --compressor.
        assert!(!s.iter().any(|a| a == "--compressor"));
    }

    #[test]
    fn standard_create_args_carry_compressor() {
        let args = targz_rafs_args(
            Path::new("/cs/layer.tgz"),
            Path::new("/w/l0/bootstrap"),
            Path::new("/w/l0"),
            "6",
            "zstd",
        );
        let s = to_strings(&args);
        assert!(s.windows(2).any(|w| w == ["--type", "targz-rafs"]));
        assert!(s.windows(2).any(|w| w == ["--compressor", "zstd"]));
    }

    #[test]
    fn directory_create_args_use_dir_rafs_and_pass_the_directory_last() {
        let args = dir_rafs_args(
            Path::new("/srv/rootfs"),
            Path::new("/w/l0/bootstrap"),
            Path::new("/w/l0"),
            "6",
            "zstd",
            &[PathBuf::from("/etc/app.conf")],
        );
        let s = to_strings(&args);
        assert!(s.windows(2).any(|w| w == ["--type", "dir-rafs"]));
        assert!(s.windows(2).any(|w| w == ["--compressor", "zstd"]));
        assert!(s.windows(2).any(|w| w == ["--fs-version", "6"]));
        assert!(s.windows(2).any(|w| w == ["--exclude", "/etc/app.conf"]));
        // The source is positional, so it must come after every flag -- and it is passed as
        // an OsString argv entry, never through a shell, so spaces and newlines are literal.
        assert_eq!(s.last().unwrap(), "/srv/rootfs");
    }

    #[test]
    fn only_appended_files_under_a_directory_are_excluded_from_its_build() {
        let appended = [
            PathBuf::from("/srv/rootfs/etc/app.conf"),
            PathBuf::from("/srv/rootfs/NOTICE"),
            // Outside the source: it has nothing to exclude from this build.
            PathBuf::from("/elsewhere/model-card.json"),
            // A sibling whose path merely starts with the same characters.
            PathBuf::from("/srv/rootfs-backup/other.conf"),
        ];
        let excludes = excludes_for_directory(Path::new("/srv/rootfs"), &appended);
        assert_eq!(
            excludes,
            vec![PathBuf::from("/etc/app.conf"), PathBuf::from("/NOTICE"),],
            "excludes are in-image paths, rooted at the source directory"
        );

        // Nothing appended means no --exclude at all, not an empty one.
        assert!(excludes_for_directory(Path::new("/srv/rootfs"), &[]).is_empty());
    }

    #[test]
    fn dual_manifest_index_layout_is_what_each_consumer_keys_on() {
        let platform = registry_client::types::Platform {
            architecture: "arm64".into(),
            os: "linux".into(),
            ..Default::default()
        };
        let oci = Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            digest: "sha256:aaaa".into(),
            size: 100,
            platform: Some(platform.clone()),
            ..Descriptor::default()
        };
        let nydus = Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            digest: "sha256:bbbb".into(),
            size: 200,
            ..Descriptor::default()
        };
        let index = dual_manifest_index(vec![oci], &nydus, &platform);

        // OCI first: a consumer that ignores the markers and takes the first platform match
        // (plain containerd, docker) must land on the standard image.
        assert_eq!(index.manifests.len(), 2);
        assert_eq!(index.manifests[0].digest, "sha256:aaaa");
        assert_eq!(index.manifests[0].artifact_type, None);
        assert!(
            index.manifests[0]
                .platform
                .as_ref()
                .is_some_and(|p| p.os_features.is_none()),
            "the OCI entry must not carry the nydus feature marker"
        );

        // The nydus entry carries BOTH markers: artifactType for current nydus parsers,
        // os.features for pre-v2.3.5 parsers and for strict platform matchers to skip.
        let n = &index.manifests[1];
        assert_eq!(n.digest, "sha256:bbbb");
        assert_eq!(
            n.artifact_type.as_deref(),
            Some("application/vnd.nydus.image.manifest.v1+json")
        );
        assert_eq!(
            n.platform.as_ref().unwrap().os_features.as_deref(),
            Some(&["nydus.remoteimage.v1".to_string()][..])
        );

        // os.features serializes under its wire name, not as Rust field casing.
        let json = serde_json::to_string(&index).unwrap();
        assert!(
            json.contains("\"os.features\":[\"nydus.remoteimage.v1\"]"),
            "{json}"
        );
        assert!(!json.contains("os_features"), "{json}");
    }

    #[test]
    fn dual_manifest_index_preserves_every_original_index_entry() {
        // Replacing a multi-arch tag must not cost the other architectures: the original
        // amd64 entry (and any attestation entries) ride along verbatim, nydus appended last.
        let platform = registry_client::types::Platform {
            architecture: "arm64".into(),
            os: "linux".into(),
            ..Default::default()
        };
        let amd64 = Descriptor {
            digest: "sha256:amd64".into(),
            platform: Some(registry_client::types::Platform {
                architecture: "amd64".into(),
                os: "linux".into(),
                ..Default::default()
            }),
            ..Descriptor::default()
        };
        let arm64 = Descriptor {
            digest: "sha256:arm64".into(),
            platform: Some(platform.clone()),
            ..Descriptor::default()
        };
        let nydus = Descriptor {
            digest: "sha256:nydus".into(),
            ..Descriptor::default()
        };
        let index = dual_manifest_index(vec![amd64, arm64], &nydus, &platform);
        assert_eq!(
            index
                .manifests
                .iter()
                .map(|m| m.digest.as_str())
                .collect::<Vec<_>>(),
            ["sha256:amd64", "sha256:arm64", "sha256:nydus"]
        );
        assert!(index.manifests[0].artifact_type.is_none());
        assert!(index.manifests[1].artifact_type.is_none());
        assert!(index.manifests[2].artifact_type.is_some());
    }

    /// A descriptor shaped like a nydus entry this tool would have written.
    fn nydus_entry(digest: &str, arch: &str, artifact_type: bool, os_feature: bool) -> Descriptor {
        Descriptor {
            digest: digest.into(),
            artifact_type: artifact_type.then(|| NYDUS_MANIFEST_ARTIFACT_TYPE.to_string()),
            platform: Some(registry_client::types::Platform {
                architecture: arch.into(),
                os: "linux".into(),
                os_features: os_feature.then(|| vec![NYDUS_OS_FEATURE.to_string()]),
                ..Default::default()
            }),
            ..Descriptor::default()
        }
    }

    #[test]
    fn reconverting_replaces_the_nydus_entry_instead_of_appending_a_second() {
        // The regression this guards: --attach-oci-manifest republishes the source index
        // verbatim, so re-converting a live tag (source == target) fed the previous run's
        // nydus entry straight back in and the index ended up advertising two.
        let platform = registry_client::types::Platform {
            architecture: "arm64".into(),
            os: "linux".into(),
            ..Default::default()
        };
        let arm64 = Descriptor {
            digest: "sha256:arm64".into(),
            platform: Some(platform.clone()),
            ..Descriptor::default()
        };
        let stale = nydus_entry("sha256:stale", "arm64", true, true);
        let fresh = Descriptor {
            digest: "sha256:fresh".into(),
            ..Descriptor::default()
        };

        let index = dual_manifest_index(vec![arm64, stale], &fresh, &platform);

        assert_eq!(
            index
                .manifests
                .iter()
                .map(|m| m.digest.as_str())
                .collect::<Vec<_>>(),
            ["sha256:arm64", "sha256:fresh"],
            "the stale nydus entry must be gone, not carried alongside the new one"
        );
        assert_eq!(
            index.manifests.iter().filter(|m| is_nydus_entry(m)).count(),
            1
        );
    }

    #[test]
    fn reconverting_is_idempotent_however_the_old_entry_was_marked() {
        // Older nydusify (and the Go tool) marked only os.features; a hand-assembled index
        // might carry only artifactType. Either alone identifies a superseded entry.
        let platform = registry_client::types::Platform {
            architecture: "arm64".into(),
            os: "linux".into(),
            ..Default::default()
        };
        let fresh = Descriptor {
            digest: "sha256:fresh".into(),
            ..Descriptor::default()
        };
        for (artifact_type, os_feature) in [(true, false), (false, true), (true, true)] {
            let stale = nydus_entry("sha256:stale", "arm64", artifact_type, os_feature);
            let index = dual_manifest_index(vec![stale], &fresh, &platform);
            assert_eq!(
                index.manifests.len(),
                1,
                "artifact_type={artifact_type} os_feature={os_feature}"
            );
            assert_eq!(index.manifests[0].digest, "sha256:fresh");
        }
    }

    #[test]
    fn reconverting_keeps_other_architectures_nydus_entries() {
        // A multi-arch tag can legitimately hold one nydus manifest per architecture,
        // produced by separate single-platform runs. Converting arm64 must not evict amd64's.
        let platform = registry_client::types::Platform {
            architecture: "arm64".into(),
            os: "linux".into(),
            ..Default::default()
        };
        let amd64_oci = Descriptor {
            digest: "sha256:amd64".into(),
            platform: Some(registry_client::types::Platform {
                architecture: "amd64".into(),
                os: "linux".into(),
                ..Default::default()
            }),
            ..Descriptor::default()
        };
        let amd64_nydus = nydus_entry("sha256:amd64-nydus", "amd64", true, true);
        let arm64_nydus = nydus_entry("sha256:arm64-nydus", "arm64", true, true);
        let fresh = Descriptor {
            digest: "sha256:fresh".into(),
            ..Descriptor::default()
        };

        let index =
            dual_manifest_index(vec![amd64_oci, amd64_nydus, arm64_nydus], &fresh, &platform);

        assert_eq!(
            index
                .manifests
                .iter()
                .map(|m| m.digest.as_str())
                .collect::<Vec<_>>(),
            ["sha256:amd64", "sha256:amd64-nydus", "sha256:fresh"]
        );
    }

    #[test]
    fn merge_args_include_original_blob_ids_only_for_oci_ref() {
        let bs = [
            PathBuf::from("/w/l0/bootstrap"),
            PathBuf::from("/w/l1/bootstrap"),
        ];
        let oci_ref = to_strings(&merge_args(
            Path::new("/w/bootstrap"),
            Some(&["d0".into(), "d1".into()]),
            &bs,
        ));
        assert!(
            oci_ref
                .windows(2)
                .any(|w| w == ["--original-blob-ids", "d0,d1"])
        );
        assert_eq!(oci_ref.last().unwrap(), "/w/l1/bootstrap");

        let standard = to_strings(&merge_args(Path::new("/w/bootstrap"), None, &bs));
        assert!(!standard.iter().any(|a| a == "--original-blob-ids"));
        // Sources still follow, lower then upper.
        assert_eq!(standard[standard.len() - 2], "/w/l0/bootstrap");
        assert_eq!(standard[standard.len() - 1], "/w/l1/bootstrap");
    }

    #[test]
    fn subject_descriptor_resolves_against_the_per_platform_manifest() {
        // The referrer subject is now the resolved per-platform (or single-arch)
        // manifest digest — so a merged multi-arch conversion attaches one
        // referrer per platform, each resolvable from its own subject, and the
        // fallback tag `check` looks up matches.
        let subject = subject_descriptor("sha256:deadbeef".to_string(), 512, true);
        assert_eq!(subject.digest, "sha256:deadbeef");
        assert_eq!(subject.size, 512);
        assert_eq!(subject.media_type, manifest_media_type(true));
        assert_eq!(
            crate::engine::artifact::fallback_referrers_tag(&subject.digest),
            "sha256-deadbeef"
        );
    }

    #[test]
    fn output_json_reports_go_parity_totals_across_platforms() {
        use registry_client::types::Platform;
        let outcome = |os: &str, arch: &str, src: u64, tgt: u64| PlatformOutcome {
            manifest: Descriptor::for_bytes(manifest_media_type(true), b"{}"),
            platform: Platform {
                architecture: arch.to_string(),
                os: os.to_string(),
                ..Default::default()
            },
            source_size: src,
            target_size: tgt,
            data_blob_count: 2,
        };
        let outcomes = vec![
            outcome("linux", "amd64", 100, 40),
            outcome("linux", "arm64", 120, 50),
        ];
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("out.json");
        let target = ImageReference::parse("registry.local/app:nydus").unwrap();
        write_output_json(&path, &target, &outcomes, 1.5).unwrap();

        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["SourceImageSize"], 220);
        assert_eq!(v["TargetImageSize"], 90);
        assert_eq!(v["ConversionElapsed"], "1.500s");
        assert_eq!(v["platforms"].as_array().unwrap().len(), 2);
        assert_eq!(v["platforms"][1]["platform"], "linux/arm64");
        // Legacy fields still describe the primary (first) platform.
        assert_eq!(v["data_blobs"], 2);
    }

    #[test]
    fn output_json_creates_missing_parent_directories() {
        use registry_client::types::Platform;
        let outcomes = vec![PlatformOutcome {
            manifest: Descriptor::for_bytes(manifest_media_type(true), b"{}"),
            platform: Platform {
                architecture: "amd64".to_string(),
                os: "linux".to_string(),
                ..Default::default()
            },
            source_size: 1,
            target_size: 1,
            data_blob_count: 1,
        }];
        let tmp = tempfile::tempdir().unwrap();
        // A namespaced image name (hashicorp/vault) yields a nested path whose
        // parent the caller never created.
        let path = tmp
            .path()
            .join("metrics")
            .join("hashicorp")
            .join("vault.json");
        let target = ImageReference::parse("registry.local/app:nydus").unwrap();

        write_output_json(&path, &target, &outcomes, 0.5).unwrap();
        assert!(path.is_file());
    }

    fn manifest_with_layer_media_type(mt: &str) -> Manifest {
        use registry_client::types::MEDIA_TYPE_OCI_CONFIG;
        let mut layer = Descriptor::for_bytes(mt, b"x");
        layer.media_type = mt.to_string();
        Manifest {
            schema_version: 2,
            media_type: None,
            artifact_type: None,
            config: Descriptor::for_bytes(MEDIA_TYPE_OCI_CONFIG, b"{}"),
            layers: vec![layer],
            subject: None,
            annotations: None,
        }
    }

    #[test]
    fn validate_layer_media_types_accepts_gzip_and_tar() {
        use registry_client::types::{
            MEDIA_TYPE_DOCKER_LAYER_TAR_GZIP, MEDIA_TYPE_OCI_LAYER_TAR,
            MEDIA_TYPE_OCI_LAYER_TAR_GZIP,
        };
        for mt in [
            MEDIA_TYPE_OCI_LAYER_TAR_GZIP,
            MEDIA_TYPE_OCI_LAYER_TAR,
            MEDIA_TYPE_DOCKER_LAYER_TAR_GZIP,
        ] {
            assert!(validate_layer_media_types(&manifest_with_layer_media_type(mt)).is_ok());
        }
    }

    #[test]
    fn validate_layer_media_types_rejects_zstd_and_foreign() {
        let zstd = validate_layer_media_types(&manifest_with_layer_media_type(
            "application/vnd.oci.image.layer.v1.tar+zstd",
        ))
        .unwrap_err();
        assert!(zstd.to_string().contains("zstd"));

        let foreign = validate_layer_media_types(&manifest_with_layer_media_type(
            "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
        ))
        .unwrap_err();
        assert!(foreign.to_string().contains("foreign"));

        let bogus =
            validate_layer_media_types(&manifest_with_layer_media_type("application/octet-stream"))
                .unwrap_err();
        assert!(bogus.to_string().contains("unsupported media type"));
    }

    #[test]
    fn prefetch_parsing_drops_root_and_empties() {
        assert!(parse_prefetch_files("/").is_empty());
        assert!(parse_prefetch_files("   ").is_empty());
        assert_eq!(
            parse_prefetch_files("/usr/bin/app\n/lib/x.so"),
            vec!["/usr/bin/app".to_string(), "/lib/x.so".to_string()]
        );
        assert_eq!(
            parse_prefetch_files("/a, /b ,/"),
            vec!["/a".to_string(), "/b".to_string()]
        );
    }

    // ---- single_output -------------------------------------------------

    #[test]
    fn single_output_finds_the_one_blob_beside_the_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = dir.path().join("bootstrap");
        std::fs::write(&bootstrap, b"boot").unwrap();
        let blob = dir.path().join("deadbeef");
        std::fs::write(&blob, b"data").unwrap();

        assert_eq!(
            single_output(dir.path(), Some(&bootstrap)).unwrap(),
            Some(blob)
        );
    }

    #[test]
    fn single_output_ignores_the_bootstrap_sidecar_a_directory_source_produces() {
        // `nydus-image create --type dir-rafs` writes `bootstrap.external` beside the
        // bootstrap; `targz-rafs` does not. Counting it as a second output made every
        // directory source fail with "produced unexpected output".
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = dir.path().join("bootstrap");
        std::fs::write(&bootstrap, b"boot").unwrap();
        std::fs::write(dir.path().join("bootstrap.external"), b"ext").unwrap();
        let blob = dir.path().join("deadbeef");
        std::fs::write(&blob, b"data").unwrap();

        assert_eq!(
            single_output(dir.path(), Some(&bootstrap)).unwrap(),
            Some(blob)
        );
    }

    #[test]
    fn layer_bootstrap_is_named_after_its_own_blob() {
        // merge derives the blob id from this file name, so two layers must never
        // end up with the same one -- that collapses the whole blob table onto a
        // single entry and produces an image referencing chunks it does not have.
        let dir = PathBuf::from("/w/l0");
        let blob_a = PathBuf::from("/w/l0/aaaa1111");
        let blob_b = PathBuf::from("/w/l1/bbbb2222");

        let a = layer_bootstrap_path(&dir, Some(&blob_a)).unwrap().unwrap();
        let b = layer_bootstrap_path(&dir, Some(&blob_b)).unwrap().unwrap();

        assert_eq!(a, PathBuf::from("/w/l0/aaaa1111.boot"));
        assert_ne!(a, b, "distinct blobs must yield distinct bootstrap names");
        // The name must not collide with the blob file itself, which sits in the
        // same directory under the bare blob id.
        assert_ne!(a, blob_a);
    }

    #[test]
    fn layer_bootstrap_keeps_its_name_when_there_is_no_blob() {
        // No blob means no blob-table entry, so merge never reads this name.
        assert_eq!(
            layer_bootstrap_path(&PathBuf::from("/w/l0"), None).unwrap(),
            None
        );
    }

    #[test]
    fn single_output_is_none_for_a_layer_with_no_data() {
        // A layer holding only directories or only whiteouts produces a
        // bootstrap and nothing else. postgres:latest ships exactly such a
        // layer (116 bytes, one empty dir), so this is not a corner case.
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = dir.path().join("bootstrap");
        std::fs::write(&bootstrap, b"boot").unwrap();

        assert_eq!(single_output(dir.path(), Some(&bootstrap)).unwrap(), None);
    }

    #[test]
    fn single_output_rejects_more_than_one_candidate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"a").unwrap();
        std::fs::write(dir.path().join("b"), b"b").unwrap();

        assert!(single_output(dir.path(), None).is_err());
    }
}
