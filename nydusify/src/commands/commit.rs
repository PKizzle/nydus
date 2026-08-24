// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! `nydusify commit` — snapshot a running container back into a nydus image.
//!
//! The container's read-write layer (the overlay `upperdir` containerd handed
//! the runtime) becomes one more RAFS layer stacked on the nydus image the
//! container was started from, and the result is published under a new tag. The
//! base image's data blobs are reused as they are, so a commit uploads only the
//! bytes the container actually wrote.
//!
//! ```text
//!   ctr container info / snapshot mounts        engine::containerd_inspect
//!            │  image ref, upperdir
//!            ▼
//!   pull the base manifest + bootstrap          registry-client
//!            │
//!            ▼
//!   upperdir ──► OCI layer tar                  engine::overlay_diff
//!            │
//!            ▼
//!   nydus-image create --type tar-rafs          -> upper blob + upper bootstrap
//!            │
//!            ▼
//!   nydus-image merge --parent-bootstrap        -> merged bootstrap
//!            │
//!            ▼
//!   push blobs + bootstrap + config + manifest  registry-client
//! ```
//!
//! ## Bind mounts
//!
//! A bind-mounted volume is a separate mount over the merged view, so nothing
//! written into it ever reaches the overlay upperdir the diff walks -- an
//! ordinary commit cannot see it at all. `--with-path` covers those: each named
//! path is tarred out of the *running* container's mount namespace with
//! `nsenter` and merged as its own layer, after the writable one, so it shadows
//! whatever the rootfs had at that location just as the mount did.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use registry_client::types::{Descriptor, Manifest, sha256_digest};
use registry_client::{ImageReference, RegistryClient};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::cli::CommitArgs;
use crate::engine::bootstrap_layer;
use crate::engine::containerd_inspect::{ContainerdCli, require_directory};
use crate::engine::manifest::{
    ANNOTATION_NYDUS_BOOTSTRAP, assemble_manifest, bootstrap_descriptor, config_media_type,
    data_blob_descriptor, manifest_media_type, rebuild_image_config, validate_nydus_manifest,
};
use crate::engine::oci::{blob_hex, client_options, fetch_nydus_platform_manifest};
use crate::engine::overlay_diff::write_upper_layer_tar;
use crate::engine::retry::RetryPolicy;

/// Annotation on the bootstrap layer listing the blobs every commit so far has
/// contributed, comma separated. `--maximum-times` is enforced against its
/// length, which is what keeps a commit loop from growing a manifest without
/// bound.
///
/// Unlike the Go nydusify — which overwrites the annotation with only the
/// current commit's blobs, so the count never grows past one — this
/// **accumulates**, which is the only reading under which `--maximum-times`
/// means anything.
pub const ANNOTATION_NYDUS_COMMIT_BLOBS: &str = "containerd.io/snapshot/nydus-commit-blobs";

/// The compressors `nydus-image create` can actually produce
/// (`src/bin/nydus-image/main.rs`, `--compressor`). A base converted with
/// `--oci-ref` reports `gzip`, because its data blobs *are* the original gzip
/// layers -- but that describes referencing an external stream, not something a
/// newly built RAFS blob can be encoded with, and `create` rejects it outright.
///
/// Falling back is safe: `RafsSuperMeta::check_compatibility`
/// (`rafs/src/metadata/mod.rs`) requires layers to agree on chunk size, RAFS
/// version and -- for v5 -- the digester, and says nothing about the
/// compressor, which RAFS records per blob.
const CREATE_COMPRESSORS: [&str; 3] = ["none", "lz4_block", "zstd"];

/// What a new layer is compressed with, given what the base reports.
fn compressor_for_new_layer(base_compressor: &str) -> &str {
    if CREATE_COMPRESSORS.contains(&base_compressor) {
        base_compressor
    } else {
        "zstd"
    }
}

/// What a commit is going to do, resolved from the flags before anything is
/// pulled, built or pushed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommitPlan {
    /// The container as the user named it (id, id prefix or nerdctl name).
    pub container: String,
    /// Where the committed image is published.
    pub target: String,
    /// An explicit `--source` override, if given.
    pub source_override: Option<String>,
    /// Platform of the base image to commit.
    pub platform: String,
    /// Absolute paths to additionally commit from inside the running container.
    pub with_path: Vec<PathBuf>,
    /// Committed-layer ceiling.
    pub maximum_times: usize,
}

/// The `--output-json` document `nydus-image` writes for `create` and `merge`.
#[derive(Debug, Default, Deserialize)]
struct NydusImageOutput {
    /// Blob ids in blob-table order (bare sha256 hex, no `sha256:` prefix).
    #[serde(default)]
    blobs: Vec<String>,
    /// RAFS filesystem version, `"5"` or `"6"`.
    #[serde(default)]
    fs_version: String,
    /// Chunk compression algorithm.
    #[serde(default)]
    compressor: String,
}

pub async fn run(args: CommitArgs) -> Result<()> {
    let plan = plan(&args)?;

    // (1) Ask containerd what the container is made of.
    let containerd = ContainerdCli {
        binary: args.containerd_cli.clone(),
        namespace: args.containerd_namespace.clone(),
        address: args.containerd_address.clone(),
    };
    let inspected = containerd
        .inspect(&plan.container)
        .with_context(|| format!("inspect container {}", plan.container))?;
    info!(
        container = %inspected.id,
        image = %inspected.image,
        snapshotter = %inspected.snapshotter,
        upper_dir = %inspected.upper_dir.display(),
        lower_dirs = inspected.lower_dirs.len(),
        "committing container"
    );
    require_directory(&inspected.upper_dir, "upper directory")?;

    let source = plan
        .source_override
        .clone()
        .unwrap_or(inspected.image.clone());
    // Publishing over the tag the container is running from would replace the
    // base image while the container is still reading blobs out of it.
    if source == plan.target {
        bail!(
            "--target {} is the image container {} is running from; commit to a new reference",
            plan.target,
            inspected.id,
        );
    }
    let source_ref =
        ImageReference::parse(&source).with_context(|| format!("parse source image {source}"))?;
    let target_ref = ImageReference::parse(&plan.target)
        .with_context(|| format!("parse --target {}", plan.target))?;
    let source_client = RegistryClient::new(
        &source_ref.api_host,
        client_options(
            args.source_insecure,
            args.plain_http || args.source_plain_http,
            &args.ca_cert,
        ),
    )
    .context("build source registry client")?;
    let target_client = RegistryClient::new(
        &target_ref.api_host,
        client_options(
            args.target_insecure,
            args.plain_http || args.target_plain_http,
            &args.ca_cert,
        ),
    )
    .context("build target registry client")?;
    let retry = RetryPolicy::from_flags(args.push_retry_count, &args.push_retry_delay);

    // (2) Pull the base nydus image: manifest, config, and bootstrap.
    let fetched = fetch_nydus_platform_manifest(
        &source_client,
        &source_ref.repo,
        source_ref.manifest_reference(),
        &plan.platform,
    )
    .await
    .with_context(|| format!("fetch base manifest {source_ref}"))?;
    let base: Manifest =
        serde_json::from_slice(&fetched.bytes).context("parse base image manifest")?;
    let base_bootstrap_desc = validate_nydus_manifest(&base).with_context(|| {
        format!(
            "{source_ref} is not a nydus image; only a container running a nydus image \
             can be committed"
        )
    })?;

    let already_committed = committed_blobs(base_bootstrap_desc);
    if already_committed.len() >= plan.maximum_times {
        bail!(
            "{source_ref} already carries {} committed layer(s), at the --maximum-times \
             limit of {}. Convert the committed image afresh with `nydusify convert` to \
             collapse them.",
            already_committed.len(),
            plan.maximum_times,
        );
    }

    let work_dir = &args.work_dir;
    std::fs::create_dir_all(work_dir)
        .with_context(|| format!("create work directory {}", work_dir.display()))?;
    let base_bootstrap = bootstrap_layer::fetch(
        &source_client,
        &source_ref.repo,
        base_bootstrap_desc,
        work_dir,
    )
    .await
    .context("pull the base image bootstrap")?;
    let config_bytes = source_client
        .get_blob(&source_ref.repo, &base.config.digest)
        .await
        .with_context(|| format!("fetch base image config {}", base.config.digest))?;

    // (3) The upper layer has to be built the way the base was, or `merge`
    // rejects it as incompatible.
    let base_info = inspect_bootstrap(&args.nydus_image, &base_bootstrap, work_dir)?;
    info!(
        fs_version = %base_info.fs_version,
        compressor = %base_info.compressor,
        blobs = base_info.blobs.len(),
        "base bootstrap"
    );

    // (4) upperdir -> OCI layer tar -> RAFS layer.
    let upper_tar = work_dir.join("blob-upper.tar");
    let stats = write_upper_layer_tar(&inspected.upper_dir, &upper_tar)
        .with_context(|| format!("diff the upper directory {}", inspected.upper_dir.display()))?;
    if stats.is_empty() {
        warn!(
            upper_dir = %inspected.upper_dir.display(),
            "the container wrote nothing; committing an empty layer"
        );
    } else {
        info!(
            files = stats.files,
            directories = stats.directories,
            whiteouts = stats.whiteouts,
            opaque_dirs = stats.opaque_dirs,
            "diffed the container's writable layer"
        );
    }

    let blob_dir = work_dir.join("commit-blobs");
    fresh_dir(&blob_dir)?;
    let upper = build_rafs_layer(
        &args.nydus_image,
        &upper_tar,
        "upper",
        &base_info,
        &blob_dir,
        work_dir,
    )?;

    // (5) `--with-path`: bind-mounted volumes live outside the writable layer,
    // so they are invisible to the upperdir walk. Read them out of the running
    // container's mount namespace instead, one layer each.
    let mut extra_layers: Vec<RafsLayer> = Vec::new();
    if !plan.with_path.is_empty() {
        let pid = containerd.task_pid(&inspected.id)?;
        info!(
            pid,
            paths = plan.with_path.len(),
            "committing extra paths from the container"
        );
        for (idx, path) in plan.with_path.iter().enumerate() {
            let tar = work_dir.join(format!("blob-mount-{idx}.tar"));
            copy_from_container(&args.nsenter, pid, path, &tar)?;
            extra_layers.push(build_rafs_layer(
                &args.nydus_image,
                &tar,
                &format!("mount-{idx}"),
                &base_info,
                &blob_dir,
                work_dir,
            )?);
        }
    }

    // (6) Stack them on the base bootstrap. The upper layer goes first and the
    // `--with-path` layers over it, so a bind-mounted path shadows whatever the
    // rootfs had at the same location -- which is what it did in the container.
    let mut sources: Vec<PathBuf> = vec![upper.bootstrap.clone()];
    sources.extend(extra_layers.iter().map(|l| l.bootstrap.clone()));
    let merged_bootstrap = work_dir.join("bootstrap-merged");
    let merge_json = work_dir.join("merge.json");
    run_nydus_image(
        &args.nydus_image,
        &merge_args(
            &base_bootstrap,
            &sources,
            &merged_bootstrap,
            &blob_dir,
            &merge_json,
        ),
        "merge the committed layer onto the base bootstrap",
    )?;
    let merged_blob_ids = read_output_json(&merge_json)?.blobs;
    debug!(?merged_blob_ids, "merged bootstrap blob table");

    // (7) Publish. Keep the base's manifest flavour: a docker-schema base stays
    // docker, an OCI base stays OCI. Some registries omit `mediaType` from the
    // manifest body, so fall back to the Content-Type it was served with.
    let docker2oci = is_oci_manifest(base.media_type.as_deref(), fetched.content_type.as_deref());
    let new_blobs: Vec<&Path> = upper
        .blob
        .iter()
        .chain(extra_layers.iter().filter_map(|l| l.blob.as_ref()))
        .map(PathBuf::as_path)
        .collect();
    let pushed = push_committed_image(
        docker2oci,
        &target_client,
        &source_client,
        &target_ref,
        &source_ref,
        &base,
        &config_bytes,
        &new_blobs,
        &merged_bootstrap,
        &merged_blob_ids,
        &already_committed,
        &base_info.fs_version,
        work_dir,
        &retry,
    )
    .await?;

    info!(
        target = %target_ref,
        manifest = %pushed.digest,
        "committed {} into {}", inspected.id, plan.target
    );
    Ok(())
}

/// Everything that touches the target registry, once the merged bootstrap is on
/// disk. Returns the pushed manifest descriptor.
#[allow(clippy::too_many_arguments)]
async fn push_committed_image(
    docker2oci: bool,
    target_client: &RegistryClient,
    source_client: &RegistryClient,
    target_ref: &ImageReference,
    source_ref: &ImageReference,
    base: &Manifest,
    config_bytes: &[u8],
    new_blobs: &[&Path],
    merged_bootstrap: &Path,
    merged_blob_ids: &[String],
    already_committed: &[String],
    fs_version: &str,
    work_dir: &Path,
    retry: &RetryPolicy,
) -> Result<Descriptor> {
    let repo = &target_ref.repo;
    // The base's data blobs are reused verbatim: same digests, same
    // annotations, so the committed image can share them with the base.
    let mut layers: Vec<Descriptor> = base
        .layers
        .iter()
        .filter(|l| !is_bootstrap_layer(l))
        .cloned()
        .collect();
    for layer in &layers {
        copy_blob_to_target(
            target_client,
            source_client,
            target_ref,
            source_ref,
            layer,
            work_dir,
            retry,
        )
        .await?;
    }

    let mut commit_blobs: Vec<String> = already_committed.to_vec();
    for blob in new_blobs {
        let digest = retry
            .run("push committed blob", || {
                target_client.push_blob_file(repo, blob)
            })
            .await
            .with_context(|| format!("push committed blob {}", blob.display()))?;
        layers.push(data_blob_descriptor(digest.clone(), file_len(blob)?));
        commit_blobs.push(digest);
    }

    // Every blob the merged bootstrap references has to be fetchable from the
    // committed image, or it mounts to a filesystem with holes in it. Checking
    // here turns that into a push-time error rather than a runtime one.
    let published: Vec<&str> = layers.iter().map(|l| blob_hex(&l.digest)).collect();
    for blob_id in merged_blob_ids {
        if !published.contains(&blob_id.as_str()) {
            bail!(
                "the merged bootstrap references blob {blob_id}, which is not among the \
                 {} layer(s) being published. The base image {source_ref} and its bootstrap \
                 disagree about their blobs.",
                layers.len(),
            );
        }
    }

    // The bootstrap travels as an ordinary gzip'd tar holding `image/image.boot`
    // — the shape containerd unpacks with no stream processor and the
    // snapshotter reads back (see engine::bootstrap_layer).
    let boot_layer = bootstrap_layer::pack(merged_bootstrap, &[])?;
    let boot_digest = retry
        .run("push committed bootstrap", || {
            target_client.push_blob_bytes(repo, &boot_layer.gzip_bytes)
        })
        .await
        .context("push the committed bootstrap")?;
    let mut bootstrap = bootstrap_descriptor(
        boot_digest,
        boot_layer.diff_id.clone(),
        boot_layer.gzip_bytes.len() as u64,
    );
    if !commit_blobs.is_empty() {
        bootstrap
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                ANNOTATION_NYDUS_COMMIT_BLOBS.to_string(),
                commit_blobs.join(","),
            );
    }
    debug!(
        fs_version,
        committed = commit_blobs.len(),
        "committed bootstrap"
    );

    // containerd requires one diff id per manifest layer. Data-blob layers are
    // uncompressed, so each is its own diff id; the bootstrap's is the digest of
    // the tar inside the gzip, which containerd recomputes while unpacking.
    let diff_ids: Vec<String> = layers
        .iter()
        .map(|l| l.digest.clone())
        .chain(std::iter::once(boot_layer.diff_id))
        .collect();
    let config_bytes = rebuild_image_config(config_bytes, &diff_ids)
        .context("rewrite the image config for the committed layer set")?;
    let config_digest = retry
        .run("push committed config", || {
            target_client.push_blob_bytes(repo, &config_bytes)
        })
        .await
        .context("push the committed image config")?;

    let config = Descriptor {
        media_type: config_media_type(docker2oci).to_string(),
        digest: config_digest,
        size: config_bytes.len() as u64,
        ..Descriptor::default()
    };
    let manifest = assemble_manifest(docker2oci, config, layers, bootstrap);
    let manifest_bytes = serde_json::to_vec(&manifest).context("serialize committed manifest")?;
    let media_type = manifest_media_type(docker2oci);
    let pushed_digest = retry
        .run("push committed manifest", || {
            target_client.push_manifest(
                repo,
                target_ref.manifest_reference(),
                media_type,
                &manifest_bytes,
            )
        })
        .await
        .with_context(|| format!("push the committed manifest to {target_ref}"))?;
    debug_assert_eq!(pushed_digest.digest, sha256_digest(&manifest_bytes));

    Ok(Descriptor {
        media_type: media_type.to_string(),
        digest: pushed_digest.digest,
        size: manifest_bytes.len() as u64,
        ..Descriptor::default()
    })
}

/// Make sure one of the base image's data blobs is readable from the target
/// repository — mounted, or copied when the registries differ.
async fn copy_blob_to_target(
    target_client: &RegistryClient,
    source_client: &RegistryClient,
    target_ref: &ImageReference,
    source_ref: &ImageReference,
    layer: &Descriptor,
    work_dir: &Path,
    retry: &RetryPolicy,
) -> Result<()> {
    let repo = &target_ref.repo;
    if target_client
        .head_blob(repo, &layer.digest)
        .await
        .unwrap_or(false)
    {
        debug!(digest = %layer.digest, "base blob already in the target repository");
        return Ok(());
    }

    if source_ref.api_host == target_ref.api_host
        && target_client
            .mount_blob(repo, &layer.digest, &source_ref.repo)
            .await
            .unwrap_or(false)
    {
        debug!(digest = %layer.digest, from = %source_ref.repo, "mounted base blob");
        return Ok(());
    }

    // Different registry (or a registry without cross-repo mount): the bytes
    // have to travel. Stage through a file so a multi-gigabyte base layer does
    // not have to fit in memory.
    let staged = work_dir.join(format!("base-{}", blob_hex(&layer.digest)));
    source_client
        .get_blob_to_file(&source_ref.repo, &layer.digest, &staged)
        .await
        .with_context(|| format!("fetch base blob {} from {source_ref}", layer.digest))?;
    let result = retry
        .run("copy base blob", || {
            target_client.push_blob_file(repo, &staged)
        })
        .await
        .with_context(|| format!("push base blob {} to {target_ref}", layer.digest));
    let _ = std::fs::remove_file(&staged);
    result?;
    debug!(digest = %layer.digest, "copied base blob to the target registry");
    Ok(())
}

/// One RAFS layer built for this commit: its data blob (absent when the layer
/// holds no file content) and the bootstrap describing it.
struct RafsLayer {
    blob: Option<PathBuf>,
    bootstrap: PathBuf,
}

/// Build one RAFS layer from a tar, at the base image's fs version and
/// compressor so `merge` accepts it.
///
/// The bootstrap is named after the blob it describes. That is not cosmetic:
/// `merge` recovers a source layer's blob id from its *bootstrap file name*
/// whenever the blob is not otherwise addressable
/// (`BlobInfo::get_blob_id_from_meta_path`), so a bootstrap called
/// `bootstrap-upper` yields a merged image referencing a blob by that name,
/// which no registry can serve. Same convention as
/// `converter::layer_bootstrap_path`.
fn build_rafs_layer(
    nydus_image: &Path,
    tar: &Path,
    label: &str,
    base: &NydusImageOutput,
    blob_dir: &Path,
    work_dir: &Path,
) -> Result<RafsLayer> {
    let staged = work_dir.join(format!("bootstrap-{label}"));
    let create_json = work_dir.join(format!("create-{label}.json"));
    run_nydus_image(
        nydus_image,
        &create_args(
            tar,
            &staged,
            blob_dir,
            &base.fs_version,
            &base.compressor,
            &create_json,
        ),
        &format!("build the {label} RAFS layer"),
    )?;

    // A layer that only deletes files, or only creates empty ones, has no
    // chunks, so `create` writes no data blob at all. That is a valid layer.
    let Some(id) = read_output_json(&create_json)?.blobs.pop() else {
        info!(
            layer = label,
            "layer holds no file data; no new blob to push"
        );
        return Ok(RafsLayer {
            blob: None,
            bootstrap: staged,
        });
    };
    let blob = blob_dir.join(&id);
    if !blob.exists() {
        bail!(
            "nydus-image reported blob {id} but wrote no file at {}",
            blob.display()
        );
    }
    info!(layer = label, blob = %id, size = file_len(&blob)?, "built a data blob");

    let bootstrap = blob_dir.join(format!("{id}.boot"));
    std::fs::rename(&staged, &bootstrap).with_context(|| {
        format!(
            "name the {label} bootstrap after its blob ({} -> {})",
            staged.display(),
            bootstrap.display()
        )
    })?;
    Ok(RafsLayer {
        blob: Some(blob),
        bootstrap,
    })
}

/// Tar an absolute path out of the running container's mount namespace.
///
/// `--with-path` exists for bind-mounted volumes: they are separate mounts over
/// the merged view, so nothing they contain ever reaches the overlay upperdir
/// an ordinary commit walks. Reading them means entering the container's mount
/// namespace, which is what `nsenter` is for.
fn copy_from_container(nsenter: &Path, pid: u32, path: &Path, out: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!(
            "--with-path {} must be absolute: it is resolved inside the container, \
             where the working directory is not ours",
            path.display()
        );
    }
    let tar = std::fs::File::create(out)
        .with_context(|| format!("create mount tar {}", out.display()))?;
    let args = nsenter_tar_args(pid, path);
    debug!(binary = %nsenter.display(), ?args, "reading a path out of the container");

    let output = Command::new(nsenter)
        .args(&args)
        .stdout(tar)
        .output()
        .with_context(|| {
            format!(
                "spawn `{}` to read {} out of the container (install util-linux, or point \
                 --nsenter at it)",
                nsenter.display(),
                path.display()
            )
        })?;
    if !output.status.success() {
        bail!(
            "reading {} out of container pid {pid} failed ({}): {}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    // `tar` warns on unreadable files rather than failing; surface that instead
    // of silently committing a partial volume.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        warn!(path = %path.display(), "tar reported: {}", stderr.trim());
    }
    info!(path = %path.display(), bytes = file_len(out)?, "read a path out of the container");
    Ok(())
}

/// `nsenter --target <pid> --mount -- tar ... -cf - <path>` args, matching what
/// the Go nydusify runs.
fn nsenter_tar_args(pid: u32, path: &Path) -> Vec<OsString> {
    vec![
        "--target".into(),
        pid.to_string().into(),
        "--mount".into(),
        "--".into(),
        "tar".into(),
        // Keep xattrs (capabilities, SELinux labels); do not abort the whole
        // commit because one file in a volume is unreadable; keep the leading
        // `/` so the entry lands at the same absolute path in the layer.
        "--xattrs".into(),
        "--ignore-failed-read".into(),
        "--absolute-names".into(),
        "-cf".into(),
        "-".into(),
        path.into(),
    ]
}

/// Read fs version, compressor and blob table out of a bootstrap, via
/// `nydus-image check -J`. The upper layer must be built with the same fs
/// version and compressor or `merge` refuses it.
fn inspect_bootstrap(
    nydus_image: &Path,
    bootstrap: &Path,
    work_dir: &Path,
) -> Result<NydusImageOutput> {
    let json = work_dir.join("base-bootstrap.json");
    run_nydus_image(
        nydus_image,
        &[
            "check".into(),
            bootstrap.into(),
            "--output-json".into(),
            json.as_os_str().into(),
        ],
        "inspect the base bootstrap",
    )?;
    let mut info = read_output_json(&json)?;
    if info.fs_version.is_empty() {
        bail!(
            "nydus-image reported no RAFS version for {}; it may not be a nydus bootstrap",
            bootstrap.display()
        );
    }
    if info.compressor.is_empty() {
        // `merge` derives the compressor from the sources anyway; default so a
        // terse builder output does not fail the commit.
        warn!("nydus-image reported no compressor for the base bootstrap; assuming zstd");
        info.compressor = "zstd".to_string();
    }
    let usable = compressor_for_new_layer(&info.compressor);
    if usable != info.compressor {
        info!(
            base_compressor = %info.compressor,
            layer_compressor = usable,
            "the base's compressor cannot be produced by nydus-image create \
             (a zran base reports the gzip of its referenced layers); compressing the \
             committed layer with {usable} instead",
        );
        info.compressor = usable.to_string();
    }
    Ok(info)
}

/// `nydus-image create --type tar-rafs` args for the committed layer.
fn create_args(
    tar: &Path,
    bootstrap_out: &Path,
    blob_dir: &Path,
    fs_version: &str,
    compressor: &str,
    output_json: &Path,
) -> Vec<OsString> {
    vec![
        "create".into(),
        "--type".into(),
        "tar-rafs".into(),
        "--fs-version".into(),
        fs_version.into(),
        "--compressor".into(),
        compressor.into(),
        // The layer speaks OCI whiteouts because engine::overlay_diff translated
        // overlayfs' markers on the way out.
        "--whiteout-spec".into(),
        "oci".into(),
        "-B".into(),
        bootstrap_out.into(),
        "-D".into(),
        blob_dir.into(),
        "--output-json".into(),
        output_json.into(),
        tar.into(),
    ]
}

/// `nydus-image merge --parent-bootstrap <base> <source>...` args. Sources are
/// listed lower-first: later ones overlay earlier ones.
fn merge_args(
    base_bootstrap: &Path,
    sources: &[PathBuf],
    bootstrap_out: &Path,
    blob_dir: &Path,
    output_json: &Path,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "merge".into(),
        "--parent-bootstrap".into(),
        base_bootstrap.into(),
        "-B".into(),
        bootstrap_out.into(),
        "-D".into(),
        blob_dir.into(),
        "--output-json".into(),
        output_json.into(),
    ];
    args.extend(sources.iter().map(OsString::from));
    args
}

/// The blobs previous commits contributed, read off the base bootstrap layer.
fn committed_blobs(bootstrap: &Descriptor) -> Vec<String> {
    bootstrap
        .annotations
        .as_ref()
        .and_then(|a| a.get(ANNOTATION_NYDUS_COMMIT_BLOBS))
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the base image is published under the OCI manifest media type (as
/// opposed to the docker schema-2 one) — `manifest_media_type`'s `docker2oci`.
fn is_oci_manifest(manifest_media_type: Option<&str>, content_type: Option<&str>) -> bool {
    manifest_media_type
        .or(content_type)
        .is_some_and(|mt| mt.contains("oci.image"))
}

/// Whether a manifest layer is the bootstrap rather than a data blob.
fn is_bootstrap_layer(layer: &Descriptor) -> bool {
    layer
        .annotations
        .as_ref()
        .is_some_and(|a| a.contains_key(ANNOTATION_NYDUS_BOOTSTRAP))
        || layer.media_type.contains("nydus.bootstrap")
        || layer.media_type.contains("bootstrap.nydus")
}

fn read_output_json(path: &Path) -> Result<NydusImageOutput> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read nydus-image output {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse nydus-image output {}", path.display()))
}

fn run_nydus_image(nydus_image: &Path, args: &[OsString], what: &str) -> Result<()> {
    debug!(binary = %nydus_image.display(), ?args, what, "running nydus-image");
    let output = Command::new(nydus_image)
        .args(args)
        .output()
        .with_context(|| format!("spawn `{}` to {what}", nydus_image.display()))?;
    if !output.status.success() {
        bail!(
            "nydus-image failed to {what} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(())
}

fn fresh_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)
            .with_context(|| format!("clear directory {}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).with_context(|| format!("create directory {}", dir.display()))
}

fn file_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len())
}

/// Validate the flags and describe the commit, without contacting anything.
pub fn plan(args: &CommitArgs) -> Result<CommitPlan> {
    if args.container.trim().is_empty() {
        bail!("--container is required and must name a running container");
    }
    if args.target.trim().is_empty() {
        bail!("--target is required and must be the reference to publish under");
    }
    if args.maximum_times == 0 {
        bail!("--maximum-times must be at least 1");
    }
    for path in &args.with_path {
        if !path.is_absolute() {
            bail!(
                "--with-path {} must be absolute: it is resolved inside the container, \
                 where the working directory is not ours",
                path.display()
            );
        }
    }
    // Committing onto the tag the container is running from would replace the
    // base image out from under it while its blobs are still being read.
    if let Some(source) = &args.source
        && source == &args.target
    {
        bail!("--source and --target are the same image ({source}); commit to a new reference");
    }
    Ok(CommitPlan {
        container: args.container.trim().to_string(),
        target: args.target.trim().to_string(),
        source_override: args.source.clone(),
        platform: args.platform.clone(),
        with_path: args.with_path.clone(),
        maximum_times: args.maximum_times,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::cli::default_platform;
    use registry_client::types::MEDIA_TYPE_NYDUS_BLOB;

    fn base_args() -> CommitArgs {
        CommitArgs {
            container: "0d1c9f1a".to_string(),
            target: "registry.example.com/app:latest-nydus-committed".to_string(),
            source: None,
            with_path: Vec::new(),
            maximum_times: 400,
            nsenter: PathBuf::from("nsenter"),
            containerd_cli: PathBuf::from("ctr"),
            containerd_namespace: "default".to_string(),
            containerd_address: None,
            source_insecure: false,
            target_insecure: false,
            plain_http: false,
            source_plain_http: false,
            target_plain_http: false,
            ca_cert: Vec::new(),
            platform: default_platform(),
            work_dir: PathBuf::from("./tmp"),
            nydus_image: PathBuf::from("nydus-image"),
            push_retry_count: 3,
            push_retry_delay: "5s".to_string(),
        }
    }

    fn bootstrap_with(annotations: &[(&str, &str)]) -> Descriptor {
        Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            digest: "sha256:beef".to_string(),
            annotations: Some(
                annotations
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            ..Descriptor::default()
        }
    }

    #[test]
    fn builds_a_plan_from_the_flags() {
        let plan = plan(&base_args()).unwrap();

        assert_eq!(plan.container, "0d1c9f1a");
        assert_eq!(
            plan.target,
            "registry.example.com/app:latest-nydus-committed"
        );
        assert!(plan.source_override.is_none());
        assert_eq!(plan.maximum_times, 400);
    }

    #[test]
    fn rejects_committing_onto_the_running_image() {
        let mut args = base_args();
        args.source = Some(args.target.clone());

        let err = plan(&args).unwrap_err();

        assert!(err.to_string().contains("same image"), "unexpected: {err}");
    }

    #[test]
    fn rejects_an_empty_container_or_target() {
        let mut args = base_args();
        args.container = "   ".to_string();
        assert!(plan(&args).unwrap_err().to_string().contains("--container"));

        let mut args = base_args();
        args.target = String::new();
        assert!(plan(&args).unwrap_err().to_string().contains("--target"));
    }

    #[test]
    fn rejects_a_zero_commit_ceiling() {
        let mut args = base_args();
        args.maximum_times = 0;

        assert!(
            plan(&args)
                .unwrap_err()
                .to_string()
                .contains("--maximum-times")
        );
    }

    #[test]
    fn counts_previously_committed_blobs_from_the_bootstrap_annotation() {
        assert!(committed_blobs(&bootstrap_with(&[])).is_empty());
        assert_eq!(
            committed_blobs(&bootstrap_with(&[(
                ANNOTATION_NYDUS_COMMIT_BLOBS,
                "sha256:aa,sha256:bb"
            )])),
            vec!["sha256:aa".to_string(), "sha256:bb".to_string()],
        );
        // Tolerate the whitespace/trailing-comma forms a hand-edited manifest
        // or another tool might produce.
        assert_eq!(
            committed_blobs(&bootstrap_with(&[(
                ANNOTATION_NYDUS_COMMIT_BLOBS,
                " sha256:aa , ,sha256:bb,"
            )])),
            vec!["sha256:aa".to_string(), "sha256:bb".to_string()],
        );
    }

    #[test]
    fn keeps_the_base_manifest_flavour() {
        assert!(is_oci_manifest(
            Some("application/vnd.oci.image.manifest.v1+json"),
            None
        ));
        assert!(!is_oci_manifest(
            Some("application/vnd.docker.distribution.manifest.v2+json"),
            None
        ));
        // Body without a mediaType: fall back to the served Content-Type.
        assert!(is_oci_manifest(
            None,
            Some("application/vnd.oci.image.manifest.v1+json")
        ));
        assert!(!is_oci_manifest(None, None));
    }

    #[test]
    fn separates_the_bootstrap_layer_from_the_data_blobs() {
        let data = Descriptor {
            media_type: MEDIA_TYPE_NYDUS_BLOB.to_string(),
            digest: "sha256:aa".to_string(),
            ..Descriptor::default()
        };
        assert!(!is_bootstrap_layer(&data));
        assert!(is_bootstrap_layer(&bootstrap_with(&[(
            ANNOTATION_NYDUS_BOOTSTRAP,
            "true"
        )])));
        // Referrer artifacts carry the raw bootstrap under its own media type.
        assert!(is_bootstrap_layer(&Descriptor {
            media_type: "application/vnd.oci.image.bootstrap.nydus.v1".to_string(),
            ..Descriptor::default()
        }));
    }

    #[test]
    fn a_zran_base_falls_back_to_a_compressor_create_can_produce() {
        // An --oci-ref base reports gzip, because its data blobs are the
        // original gzip layers. `nydus-image create` only accepts
        // none/lz4_block/zstd and fails the build on anything else.
        assert_eq!(compressor_for_new_layer("gzip"), "zstd");
        // Anything create understands is passed through untouched.
        assert_eq!(compressor_for_new_layer("zstd"), "zstd");
        assert_eq!(compressor_for_new_layer("lz4_block"), "lz4_block");
        assert_eq!(compressor_for_new_layer("none"), "none");
        // An unrecognised value is a fallback too, not a build failure.
        assert_eq!(compressor_for_new_layer("brotli"), "zstd");
    }

    #[test]
    fn create_args_pin_the_base_layout_and_oci_whiteouts() {
        let args = create_args(
            Path::new("/w/blob-upper.tar"),
            Path::new("/w/bootstrap-upper"),
            Path::new("/w/blobs"),
            "6",
            "zstd",
            Path::new("/w/create.json"),
        );
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert_eq!(args[0], "create");
        assert!(args.windows(2).any(|w| w == ["--type", "tar-rafs"]));
        assert!(args.windows(2).any(|w| w == ["--fs-version", "6"]));
        assert!(args.windows(2).any(|w| w == ["--compressor", "zstd"]));
        assert!(args.windows(2).any(|w| w == ["--whiteout-spec", "oci"]));
        // The tar is the positional source and must come last.
        assert_eq!(args.last().unwrap(), "/w/blob-upper.tar");
    }

    #[test]
    fn rejects_a_relative_with_path() {
        let mut args = base_args();
        args.with_path = vec![PathBuf::from("var/lib/data")];

        let err = plan(&args).unwrap_err();

        assert!(
            err.to_string().contains("must be absolute"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn carries_absolute_with_paths_into_the_plan() {
        let mut args = base_args();
        args.with_path = vec![PathBuf::from("/data"), PathBuf::from("/srv/cache")];

        let plan = plan(&args).unwrap();

        assert_eq!(
            plan.with_path,
            vec![PathBuf::from("/data"), PathBuf::from("/srv/cache")]
        );
    }

    #[test]
    fn nsenter_args_enter_the_mount_namespace_and_keep_absolute_names() {
        let args: Vec<String> = nsenter_tar_args(31337, Path::new("/data"))
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert!(args.windows(2).any(|w| w == ["--target", "31337"]));
        assert!(args.contains(&"--mount".to_string()));
        // Everything after `--` is the command run inside the namespace.
        let sep = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[sep + 1], "tar");
        // Without --absolute-names tar strips the leading `/` and the entry
        // lands at the wrong place in the layer.
        assert!(args.contains(&"--absolute-names".to_string()));
        assert!(args.contains(&"--xattrs".to_string()));
        assert!(args.contains(&"--ignore-failed-read".to_string()));
        // Streamed to stdout, with the path last.
        assert!(args.windows(2).any(|w| w == ["-cf", "-"]));
        assert_eq!(args.last().unwrap(), "/data");
    }

    #[test]
    fn merge_lists_with_path_layers_after_the_upper_one() {
        // Later sources overlay earlier ones, so a bind-mounted path has to come
        // after the writable layer -- it shadowed the rootfs in the container.
        let sources = vec![
            PathBuf::from("/w/blobs/aa.boot"),
            PathBuf::from("/w/blobs/bb.boot"),
        ];
        let args: Vec<String> = merge_args(
            Path::new("/w/bootstrap-base"),
            &sources,
            Path::new("/w/bootstrap-merged"),
            Path::new("/w/blobs"),
            Path::new("/w/merge.json"),
        )
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

        assert_eq!(
            &args[args.len() - 2..],
            &[
                "/w/blobs/aa.boot".to_string(),
                "/w/blobs/bb.boot".to_string()
            ]
        );
    }

    #[test]
    fn merge_args_stack_the_upper_layer_on_the_base_bootstrap() {
        let args = merge_args(
            Path::new("/w/bootstrap-base"),
            &[PathBuf::from("/w/bootstrap-upper")],
            Path::new("/w/bootstrap-merged"),
            Path::new("/w/blobs"),
            Path::new("/w/merge.json"),
        );
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert_eq!(args[0], "merge");
        assert!(
            args.windows(2)
                .any(|w| w == ["--parent-bootstrap", "/w/bootstrap-base"])
        );
        assert!(args.windows(2).any(|w| w == ["-B", "/w/bootstrap-merged"]));
        // Only the upper bootstrap is a source; the base comes in as the parent
        // and must not also be listed as one, which would merge it into itself.
        assert_eq!(args.last().unwrap(), "/w/bootstrap-upper");
        assert_eq!(args.iter().filter(|a| *a == "/w/bootstrap-base").count(), 1);
    }

    #[test]
    fn parses_the_builder_output_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        std::fs::write(
            &path,
            r#"{"version":"x","bootstrap":"/w/b","blobs":["aa","bb"],
                "fs_version":"6","compressor":"zstd","trace":{}}"#,
        )
        .unwrap();

        let output = read_output_json(&path).unwrap();

        assert_eq!(output.blobs, vec!["aa".to_string(), "bb".to_string()]);
        assert_eq!(output.fs_version, "6");
        assert_eq!(output.compressor, "zstd");
    }
}
