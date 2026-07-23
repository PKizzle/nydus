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

use crate::commands::convert::ConversionMode;
use crate::engine::artifact::maybe_push_referrer;
use crate::engine::containerd_converter::ConvertRequest;
use crate::engine::manifest::{
    assemble_index, assemble_manifest, bootstrap_descriptor, config_media_type,
    data_blob_descriptor, index_media_type, manifest_media_type, rebuild_image_config,
};
use crate::engine::oci::{
    all_platform_selectors, blob_hex, client_options, is_index, parse_platform_list,
    select_platform,
};
use crate::engine::retry::RetryPolicy;

/// A source rootfs layer pulled to disk.
#[derive(Clone, Debug)]
struct PulledLayer {
    /// OCI digest (`sha256:<hex>`) of the (gzip) layer blob.
    digest: String,
    /// On-disk path of the downloaded layer blob.
    path: PathBuf,
}

/// The pulled source image (single platform).
struct PulledSource {
    /// Descriptor the referrer artifact is published against. For a
    /// single-platform convert of a single-arch source this is the source
    /// manifest; for one platform of a multi-arch source it is that
    /// platform's manifest (so a merged conversion attaches one referrer per
    /// platform, each resolvable from its own subject).
    referrer_subject: Descriptor,
    /// The platform this manifest targets (index entry + reporting).
    platform: registry_client::types::Platform,
    /// Sum of the source layer (compressed) sizes, for `--output-json`.
    source_size: u64,
    /// Raw image-config JSON, reused verbatim as the nydus image config.
    config_bytes: Vec<u8>,
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

    let source_ref = ImageReference::parse(&request.source)
        .with_context(|| format!("parse --source {}", request.source))?;
    let target_ref = ImageReference::parse(&request.target)
        .with_context(|| format!("parse --target {}", request.target))?;

    let source_client = RegistryClient::new(
        &source_ref.api_host,
        client_options(
            request.source_insecure,
            request.plain_http,
            &request.ca_cert_files,
        ),
    )
    .context("build source registry client")?;
    let target_client = RegistryClient::new(
        &target_ref.api_host,
        client_options(
            request.target_insecure,
            request.plain_http,
            &request.ca_cert_files,
        ),
    )
    .context("build target registry client")?;
    let same_registry = source_ref.api_host == target_ref.api_host;
    let retry = RetryPolicy::from_flags(request.push_retry_count, &request.push_retry_delay);

    // Resolve which platforms to convert from the top-level source reference.
    let plan = resolve_platform_plan(request, &source_client, &source_ref).await?;

    if plan.selectors.len() == 1 {
        // Single platform: push the manifest directly at the target tag —
        // byte-for-byte the pre-multi-platform behavior (no index wrapper).
        let outcome = convert_one_platform(
            request,
            &source_client,
            &target_client,
            &source_ref,
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
            &source_client,
            &target_client,
            &source_ref,
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
    source_client: &RegistryClient,
    target_client: &RegistryClient,
    source_ref: &ImageReference,
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
    let source = pull_source(request, source_client, source_ref, platform, workspace).await?;
    info!(
        source = %source_ref,
        platform = %platform,
        layers = source.layers.len(),
        oci_ref = request.driver.oci_ref,
        "pulled source image; building nydus artifact"
    );

    // ---- build (nydus-image subprocess) ----
    let output = build_artifact(request, &source.layers, workspace)?;

    // ---- push ----
    let pushed = push_artifact(
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
    .await?;

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
    maybe_push_referrer(
        request.driver.with_referrer,
        source_client,
        &source_ref.repo,
        &data_blob_files,
        &output.bootstrap,
        &source.referrer_subject,
        retry,
    )
    .await?;

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
    if request.source_archive.is_some() || request.target_archive.is_some() {
        bail!(
            "--source-archive/--target-archive (OCI archive I/O) is not yet supported by nydusify-rs (follow-up)"
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
    let (image_bytes, image_digest, plat) =
        if is_index(fetched.content_type.as_deref(), &fetched.bytes) {
            let index: Index =
                serde_json::from_slice(&fetched.bytes).context("parse source image index")?;
            let selected = select_platform(&index, platform)?;
            let plat = selected.platform.clone().unwrap_or_default();
            let img = client
                .get_manifest(repo, &selected.digest)
                .await
                .with_context(|| format!("fetch platform manifest {}", selected.digest))?;
            (img.bytes, img.digest, plat)
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
            (fetched.bytes, fetched.digest, plat)
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
        referrer_subject,
        platform: plat,
        source_size,
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
    layers: &[PulledLayer],
    workspace: &Path,
) -> Result<ConversionOutput> {
    let nydus_image = request.driver.builder.as_path();
    let fs_version = request.driver.fs_version.as_str();
    let convert_root = workspace.join("convert");
    std::fs::create_dir_all(&convert_root)?;

    let mut layer_bootstraps = Vec::with_capacity(layers.len());
    let mut new_blobs = Vec::new();
    let mut original_blob_ids = Vec::with_capacity(layers.len());

    for (i, layer) in layers.iter().enumerate() {
        let out_dir = convert_root.join(format!("l{i}-{}", blob_hex(&layer.digest)));
        fresh_dir(&out_dir)?;
        let bootstrap_i = out_dir.join("bootstrap");
        let args = if request.driver.oci_ref {
            targz_ref_args(&layer.path, &bootstrap_i, &out_dir, fs_version)
        } else {
            targz_rafs_args(
                &layer.path,
                &bootstrap_i,
                &out_dir,
                fs_version,
                &request.driver.compressor,
            )
        };
        run_nydus_image(nydus_image, &args, "create")?;
        let blob = expect_single_output(&out_dir, Some(&bootstrap_i))
            .context("locating per-layer nydus data blob")?;

        layer_bootstraps.push(bootstrap_i);
        new_blobs.push(blob);
        original_blob_ids.push(blob_hex(&layer.digest).to_string());
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
        layers.to_vec()
    } else {
        Vec::new()
    };

    // Optional prefetch optimization.
    let prefetch_files = parse_prefetch_files(&request.driver.prefetch_patterns);
    if !prefetch_files.is_empty() {
        match run_optimize(
            nydus_image,
            workspace,
            &bootstrap,
            &new_blobs,
            &reused_layers,
            &prefetch_files,
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
fn run_optimize(
    nydus_image: &Path,
    workspace: &Path,
    bootstrap: &Path,
    new_blobs: &[PathBuf],
    reused_layers: &[PulledLayer],
    prefetch_files: &[String],
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
    let json = serde_json::json!({
        "version": "v1",
        "files": prefetch_files
            .iter()
            .map(|p| serde_json::json!({ "path": p, "ranges": null }))
            .collect::<Vec<_>>(),
    });
    std::fs::write(&prefetch_json, serde_json::to_vec(&json)?)
        .with_context(|| format!("write {}", prefetch_json.display()))?;

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
    let prefetch_blob =
        expect_single_output(&out_blob_dir, None).context("locating optimize prefetch blob")?;
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

#[allow(clippy::too_many_arguments)]
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
    source_ref: &ImageReference,
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
        let mounted = if same_registry && source_ref.repo != target_ref.repo {
            client
                .mount_blob(repo, &layer.digest, &source_ref.repo)
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

    // Bootstrap.
    let boot_digest = retry
        .run("push nydus bootstrap", || {
            client.push_blob_file(repo, &output.bootstrap)
        })
        .await
        .context("push nydus bootstrap")?;
    let bootstrap = bootstrap_descriptor(boot_digest, file_len(&output.bootstrap)?);

    // Rebuild the image config so `rootfs.diff_ids` has exactly one entry per
    // pushed manifest layer (data blobs first, bootstrap last) — otherwise
    // containerd rejects the image with "mismatched image rootfs and manifest
    // layers". Push the NEW config blob and reference it in the manifest.
    let layer_digests: Vec<String> = data_blobs
        .iter()
        .map(|d| d.digest.clone())
        .chain(std::iter::once(bootstrap.digest.clone()))
        .collect();
    let config_bytes = rebuild_image_config(&source.config_bytes, &layer_digests)
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

/// Return the single file in `dir` other than `exclude`. More than one
/// candidate in a freshly-wiped private dir means `nydus-image` produced
/// unexpected output — a real bug, surfaced.
fn expect_single_output(dir: &Path, exclude: Option<&Path>) -> Result<PathBuf> {
    let exclude_name = exclude.and_then(Path::file_name);
    let mut found = None;
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("reading output dir {}", dir.display()))?
    {
        let entry = entry?;
        if !entry.path().is_file() || Some(entry.file_name().as_os_str()) == exclude_name {
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
    found.ok_or_else(|| anyhow!("nydus-image produced no output file in {}", dir.display()))
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
}
