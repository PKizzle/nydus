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
//!   target, else re-pushed) plus tiny per-layer zran index blobs — the
//!   B4b-served shape.
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
    assemble_manifest, bootstrap_descriptor, config_media_type, data_blob_descriptor,
    manifest_media_type,
};
use crate::engine::oci::{blob_hex, client_options, is_index, select_platform};

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
    /// Descriptor of the source image manifest (captured for the P4c referrer
    /// seam: it becomes the referrer artifact `subject`).
    manifest_desc: Descriptor,
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

    let source_ref = ImageReference::parse(&request.source)
        .with_context(|| format!("parse --source {}", request.source))?;
    let target_ref = ImageReference::parse(&request.target)
        .with_context(|| format!("parse --target {}", request.target))?;

    let source_client = RegistryClient::new(
        &source_ref.api_host,
        client_options(request.source_insecure, request.plain_http),
    )
    .context("build source registry client")?;

    // ---- pull ----
    let source = pull_source(request, &source_client, &source_ref, workspace).await?;
    info!(
        source = %source_ref,
        layers = source.layers.len(),
        oci_ref = request.driver.oci_ref,
        "pulled source image; building nydus artifact"
    );

    // ---- build (nydus-image subprocess) ----
    let output = build_artifact(request, &source.layers, workspace)?;

    // ---- push ----
    let target_client = RegistryClient::new(
        &target_ref.api_host,
        client_options(request.target_insecure, request.plain_http),
    )
    .context("build target registry client")?;
    let same_registry = source_ref.api_host == target_ref.api_host;

    let pushed = push_artifact(
        request,
        &target_client,
        &target_ref,
        &source_ref,
        same_registry,
        &source,
        &output,
    )
    .await?;

    // ---- P4c: attach a referrer artifact to the source image ----
    // Data blobs in image-layer order: reused gzip layers (oci-ref) then the
    // newly-built nydus blobs. Pushed to the source repo so the referrer
    // resolves alongside its subject.
    let mut data_blob_files: Vec<PathBuf> = output
        .reused_layers
        .iter()
        .map(|l| l.path.clone())
        .collect();
    data_blob_files.extend(output.new_blobs.iter().cloned());
    maybe_push_referrer(
        request.driver.with_referrer,
        &source_client,
        &source_ref.repo,
        &data_blob_files,
        &output.bootstrap,
        &source.manifest_desc,
    )
    .await?;

    if let Some(path) = &request.output_json {
        write_output_json(path, &target_ref, &pushed, &output)?;
    }

    info!(
        target = %target_ref,
        manifest = %pushed.digest,
        data_blobs = output.reused_layers.len() + output.new_blobs.len(),
        "convert complete: pushed nydus image"
    );
    Ok(())
}

/// Reject the v1-out-of-scope knobs with honest errors instead of silently
/// mis-converting.
fn reject_unsupported(request: &ConvertRequest) -> Result<()> {
    if request.mode == ConversionMode::Reverse {
        bail!("--reverse (nydus->OCI) conversion is not yet supported by nydusify-rs (follow-up)");
    }
    if request.all_platforms {
        bail!(
            "--all-platforms is not yet supported by nydusify-rs; convert one platform at a time with --platform (follow-up)"
        );
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
    Ok(())
}

// ---------------------------------------------------------------------------
// Pull
// ---------------------------------------------------------------------------

async fn pull_source(
    request: &ConvertRequest,
    client: &RegistryClient,
    source_ref: &ImageReference,
    workspace: &Path,
) -> Result<PulledSource> {
    let repo = &source_ref.repo;
    let fetched = client
        .get_manifest(repo, source_ref.manifest_reference())
        .await
        .with_context(|| format!("fetch source manifest {source_ref}"))?;

    // Resolve an index/manifest-list down to a single platform manifest.
    let (image_bytes, image_digest, image_content_type) =
        if is_index(fetched.content_type.as_deref(), &fetched.bytes) {
            let index: Index =
                serde_json::from_slice(&fetched.bytes).context("parse source image index")?;
            let selected = select_platform(&index, &request.platforms)?;
            let img = client
                .get_manifest(repo, &selected.digest)
                .await
                .with_context(|| format!("fetch platform manifest {}", selected.digest))?;
            (img.bytes, img.digest, img.content_type)
        } else {
            (fetched.bytes, fetched.digest, fetched.content_type)
        };

    let manifest: Manifest =
        serde_json::from_slice(&image_bytes).context("parse source image manifest")?;
    if manifest.layers.is_empty() {
        bail!("source image manifest {image_digest} has no layers");
    }

    let manifest_desc = Descriptor {
        media_type: image_content_type
            .clone()
            .unwrap_or_else(|| manifest_media_type(true).to_string()),
        digest: image_digest.clone(),
        size: image_bytes.len() as u64,
        ..Descriptor::default()
    };

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
        manifest_desc,
        config_bytes,
        layers,
    })
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

    std::fs::rename(&optimized, bootstrap)
        .context("replace merged bootstrap with optimized one")?;
    expect_single_output(&out_blob_dir, None).context("locating optimize prefetch blob")
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
async fn push_artifact(
    request: &ConvertRequest,
    client: &RegistryClient,
    target_ref: &ImageReference,
    source_ref: &ImageReference,
    same_registry: bool,
    source: &PulledSource,
    output: &ConversionOutput,
) -> Result<Descriptor> {
    let repo = &target_ref.repo;
    let docker2oci = request.driver.docker2oci;

    // Config blob (reused verbatim from the source image).
    let config_digest = client
        .push_blob_bytes(repo, &source.config_bytes)
        .await
        .context("push image config")?;
    let config = Descriptor {
        media_type: config_media_type(docker2oci).to_string(),
        digest: config_digest,
        size: source.config_bytes.len() as u64,
        ..Descriptor::default()
    };

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
            client
                .push_blob_file(repo, &layer.path)
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
        let digest = client
            .push_blob_file(repo, blob)
            .await
            .with_context(|| format!("push nydus blob {}", blob.display()))?;
        data_blobs.push(data_blob_descriptor(digest, file_len(blob)?));
    }

    // Bootstrap.
    let boot_digest = client
        .push_blob_file(repo, &output.bootstrap)
        .await
        .context("push nydus bootstrap")?;
    let bootstrap = bootstrap_descriptor(boot_digest, file_len(&output.bootstrap)?);

    // Manifest.
    let manifest = assemble_manifest(docker2oci, config, data_blobs, bootstrap);
    let manifest_bytes = serde_json::to_vec(&manifest).context("serialize nydus manifest")?;
    let media_type = manifest_media_type(docker2oci);
    let reference = target_ref.manifest_reference();
    let manifest_digest = client
        .push_manifest(repo, reference, media_type, &manifest_bytes)
        .await
        .with_context(|| format!("push nydus manifest to {target_ref}"))?;

    Ok(Descriptor {
        media_type: media_type.to_string(),
        digest: manifest_digest,
        size: manifest_bytes.len() as u64,
        ..Descriptor::default()
    })
}

fn write_output_json(
    path: &Path,
    target_ref: &ImageReference,
    pushed: &Descriptor,
    output: &ConversionOutput,
) -> Result<()> {
    let summary = serde_json::json!({
        "target": target_ref.to_string(),
        "manifest_digest": pushed.digest,
        "manifest_size": pushed.size,
        "data_blobs": output.reused_layers.len() + output.new_blobs.len(),
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
