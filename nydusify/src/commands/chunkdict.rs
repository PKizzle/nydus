// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! `nydusify chunkdict generate`: train a shared chunk dictionary across
//! several already-converted nydus images and publish it as a nydus image of
//! its own.
//!
//! The dictionary is what `nydus-image chunkdict generate` produces: it loads
//! every source bootstrap into a SQLite database, finds the chunks they have in
//! common, and emits one bootstrap referencing the deduplicated set. Converting
//! a new image with `--chunk-dict <that image>` then lets it reuse those chunks
//! instead of re-uploading them.
//!
//! Two contracts from the builder side are load-bearing here:
//!
//! * `nydus-image` derives each source's image name and tag from the **parent
//!   directory name** of its bootstrap, splitting on `:` and taking the last two
//!   components. So every bootstrap is staged at
//!   `<work-dir>/<ref with '/' replaced by ':'>/nydus_bootstrap` — a layout the
//!   Go nydusify established and the builder still parses.
//! * The `blobs` in its output JSON are bare hex blob ids. The corresponding
//!   registry blob is `sha256:<id>`, which is exactly how the source images'
//!   data-blob layers are addressed, so the dictionary image reuses those blobs
//!   rather than producing new ones.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use registry_client::types::Manifest;
use registry_client::{Descriptor, ImageReference, RegistryClient};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::cli::ChunkdictArgs;
use crate::engine::bootstrap_layer;
use crate::engine::manifest::{
    assemble_manifest, bootstrap_descriptor, config_media_type, data_blob_descriptor,
    manifest_media_type, rebuild_image_config, validate_nydus_manifest,
};
use crate::engine::oci::{client_options, fetch_platform_manifest};
use crate::engine::retry::RetryPolicy;

/// File name `nydus-image` expects inside each staged source directory.
const STAGED_BOOTSTRAP_NAME: &str = "nydus_bootstrap";

/// The subset of `nydus-image`'s output JSON this command consumes.
#[derive(Debug, Deserialize)]
struct BuildOutput {
    /// Bare hex blob ids making up the deduplicated set.
    #[serde(default)]
    blobs: Vec<String>,
}

/// One resolved source image: where it came from and what it is made of.
struct SourceImage {
    reference: ImageReference,
    manifest: Manifest,
    /// Bootstrap staged where `nydus-image` can infer a name/tag from it.
    staged_bootstrap: PathBuf,
}

pub async fn run(args: ChunkdictArgs) -> Result<()> {
    let sources = parse_sources(&args.sources)?;
    let target_ref = ImageReference::parse(&args.target)
        .with_context(|| format!("parse --target {}", args.target))?;

    std::fs::create_dir_all(&args.work_dir)
        .with_context(|| format!("create --work-dir {}", args.work_dir.display()))?;
    // nydus-image is handed a `sqlite://<path>` URL and rejects a relative one,
    // so the work dir has to be absolute before it is composed in.
    let work_dir = std::path::absolute(&args.work_dir)
        .with_context(|| format!("resolve --work-dir {}", args.work_dir.display()))?;

    let source_plain_http = args.plain_http || args.source_plain_http;
    let target_plain_http = args.plain_http || args.target_plain_http;

    // (1) Stage every source bootstrap under the name nydus-image parses.
    let mut staged = Vec::with_capacity(sources.len());
    for source in &sources {
        staged.push(stage_source(source, &args, source_plain_http, &work_dir).await?);
    }

    // (2) Train the dictionary.
    let chunkdict_bootstrap = work_dir.join("chunkdict_bootstrap");
    let output_json = work_dir.join("nydus_bootstrap_output.json");
    run_chunkdict_generate(
        &args.nydus_image,
        &chunkdict_bootstrap,
        &work_dir,
        &output_json,
        &staged,
    )?;

    let output: BuildOutput = serde_json::from_slice(
        &std::fs::read(&output_json)
            .with_context(|| format!("read chunkdict output {}", output_json.display()))?,
    )
    .with_context(|| format!("parse chunkdict output {}", output_json.display()))?;

    let blob_ids = dedup_blob_ids(&output.blobs);
    if blob_ids.is_empty() {
        // An empty dictionary is a legitimate answer, not a failure: the
        // selection in `nydus-image` clusters images with DBSCAN at
        // `min_points = 10` (src/bin/nydus-image/deduplicate.rs), so a handful
        // of sources can never form a cluster and every one of them comes back
        // a noise point. Say so and publish the bootstrap anyway — the caller
        // asked for an artifact at `--target`, and exiting 0 while quietly
        // pushing nothing is the worse failure.
        warn!(
            sources = sources.len(),
            "the trained dictionary is empty, so the published image carries no data layers. \
             nydus-image clusters sources with DBSCAN (min_points = 10); train from more \
             images, or from more versions of the same image, to get a dictionary worth using"
        );
    } else {
        info!(
            blobs = blob_ids.len(),
            sources = sources.len(),
            "trained chunk dictionary"
        );
    }

    // (3) Publish it as a nydus image.
    push_chunkdict_image(
        &args,
        &staged,
        &target_ref,
        target_plain_http,
        &blob_ids,
        &chunkdict_bootstrap,
    )
    .await
}

/// Split `--sources` into individual references.
///
/// Accepts the comma-separated form the Go tool documents as well as a repeated
/// flag, and rejects an empty entry rather than turning it into a bogus ref.
pub fn parse_sources(sources: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in sources {
        for part in entry.split(',') {
            let part = part.trim();
            if part.is_empty() {
                bail!("--sources contains an empty reference: {entry:?}");
            }
            out.push(part.to_string());
        }
    }
    if out.len() < 2 {
        bail!(
            "chunkdict needs at least two source images to find shared chunks, got {}",
            out.len()
        );
    }
    Ok(out)
}

/// Directory name `nydus-image` parses an image name and tag out of.
///
/// It splits on `:` and takes the last two components, so `/` has to become `:`
/// for `localhost:5077/redis:7.0.1` to yield name `redis`, tag `7.0.1`.
pub fn staging_dir_name(reference: &str) -> String {
    reference.replace('/', ":")
}

/// Pull one source's manifest and stage its bootstrap for the builder.
async fn stage_source(
    source: &str,
    args: &ChunkdictArgs,
    plain_http: bool,
    work_dir: &Path,
) -> Result<SourceImage> {
    let reference =
        ImageReference::parse(source).with_context(|| format!("parse source {source}"))?;
    let client = RegistryClient::new(
        &reference.api_host,
        client_options(args.source_insecure, plain_http, &args.ca_cert),
    )
    .with_context(|| format!("build registry client for {source}"))?;

    let fetched = fetch_platform_manifest(
        &client,
        &reference.repo,
        reference.manifest_reference(),
        &args.platform,
    )
    .await
    .with_context(|| format!("fetch manifest {source}"))?;
    let manifest: Manifest = serde_json::from_slice(&fetched.bytes)
        .with_context(|| format!("parse manifest {source}"))?;
    let bootstrap = validate_nydus_manifest(&manifest)
        .with_context(|| format!("{source} is not a valid nydus image"))?;

    let dir = work_dir.join(staging_dir_name(source));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create source staging dir {}", dir.display()))?;
    let staged_bootstrap = bootstrap_layer::fetch(&client, &reference.repo, bootstrap, &dir)
        .await
        .with_context(|| format!("fetch bootstrap of {source}"))?;
    // `fetch` writes `<dir>/bootstrap`; the builder wants `nydus_bootstrap`.
    let renamed = dir.join(STAGED_BOOTSTRAP_NAME);
    if staged_bootstrap != renamed {
        std::fs::rename(&staged_bootstrap, &renamed).with_context(|| {
            format!(
                "stage bootstrap {} -> {}",
                staged_bootstrap.display(),
                renamed.display()
            )
        })?;
    }
    debug!(%source, staged = %renamed.display(), "staged source bootstrap");

    Ok(SourceImage {
        reference,
        manifest,
        staged_bootstrap: renamed,
    })
}

/// Build the `nydus-image chunkdict generate` argument list.
///
/// Split out so the exact contract — notably the `sqlite://` URL, which the
/// builder rejects unless absolute — is unit-testable without running anything.
pub fn chunkdict_generate_args(
    bootstrap_out: &Path,
    work_dir: &Path,
    output_json: &Path,
    bootstraps: &[PathBuf],
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "chunkdict".into(),
        "generate".into(),
        "--log-level".into(),
        "warn".into(),
        "--bootstrap".into(),
        bootstrap_out.into(),
        "--database".into(),
        format!("sqlite://{}", work_dir.join("database.db").display()).into(),
        "--output-json".into(),
        output_json.into(),
        "-D".into(),
        work_dir.into(),
    ];
    args.extend(bootstraps.iter().map(OsString::from));
    args
}

fn run_chunkdict_generate(
    nydus_image: &Path,
    bootstrap_out: &Path,
    work_dir: &Path,
    output_json: &Path,
    sources: &[SourceImage],
) -> Result<()> {
    let bootstraps: Vec<PathBuf> = sources.iter().map(|s| s.staged_bootstrap.clone()).collect();
    let args = chunkdict_generate_args(bootstrap_out, work_dir, output_json, &bootstraps);

    let output = Command::new(nydus_image)
        .args(&args)
        .output()
        .with_context(|| format!("spawn `{}` chunkdict generate", nydus_image.display()))?;
    if !output.status.success() {
        bail!(
            "nydus-image chunkdict generate failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Deduplicate the blob ids, preserving first-seen order.
pub fn dedup_blob_ids(blobs: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    blobs
        .iter()
        .filter(|id| !id.is_empty())
        .filter(|id| seen.insert((*id).clone()))
        .cloned()
        .collect()
}

/// Look up a blob's size from whichever source manifest carries it.
///
/// The dictionary's blobs all come from the sources, so their descriptors are
/// already known; this avoids a HEAD per blob.
fn blob_size(sources: &[SourceImage], digest: &str) -> Option<u64> {
    sources.iter().find_map(|s| {
        s.manifest
            .layers
            .iter()
            .find(|l| l.digest == digest)
            .map(|l| l.size)
    })
}

async fn push_chunkdict_image(
    args: &ChunkdictArgs,
    sources: &[SourceImage],
    target_ref: &ImageReference,
    plain_http: bool,
    blob_ids: &[String],
    chunkdict_bootstrap: &Path,
) -> Result<()> {
    let client = RegistryClient::new(
        &target_ref.api_host,
        client_options(args.target_insecure, plain_http, &args.ca_cert),
    )
    .context("build target registry client")?;
    let retry = RetryPolicy::from_flags(args.push_retry_count, &args.push_retry_delay);

    // The dictionary's data blobs already exist in the source repos, so they are
    // cross-repo mounted where the registry allows it and only re-pushed when it
    // does not. A blob whose bytes we never downloaded cannot be pushed, so a
    // failed mount against a different registry is a hard error rather than a
    // silent half-image.
    let mut data_blobs = Vec::with_capacity(blob_ids.len());
    for id in blob_ids {
        let digest = format!("sha256:{id}");
        let size = blob_size(sources, &digest).with_context(|| {
            format!("blob {digest} from the chunk dictionary is not in any source manifest")
        })?;

        if !client
            .head_blob(&target_ref.repo, &digest)
            .await
            .unwrap_or(false)
        {
            let mut mounted = false;
            for source in sources {
                if source.reference.api_host == target_ref.api_host
                    && client
                        .mount_blob(&target_ref.repo, &digest, &source.reference.repo)
                        .await
                        .unwrap_or(false)
                {
                    mounted = true;
                    break;
                }
            }
            if !mounted {
                bail!(
                    "cannot place dictionary blob {digest} in {}: it lives in the source \
                     registry and cross-repo mount was refused or unavailable. Publish the \
                     dictionary to the same registry as its sources.",
                    target_ref.repo
                );
            }
            debug!(digest = %digest, "mounted dictionary blob from source repo");
        }
        data_blobs.push(data_blob_descriptor(digest, size));
    }

    // Bootstrap, as the same gzip'd tar layer every other nydus image uses.
    let boot_layer = bootstrap_layer::pack(chunkdict_bootstrap, &[])?;
    let boot_digest = retry
        .run("push chunkdict bootstrap", || {
            client.push_blob_bytes(&target_ref.repo, &boot_layer.gzip_bytes)
        })
        .await
        .context("push chunkdict bootstrap")?;
    let bootstrap = bootstrap_descriptor(
        boot_digest,
        boot_layer.diff_id.clone(),
        boot_layer.gzip_bytes.len() as u64,
    );

    // Reuse the first source's config so the dictionary image carries a sane
    // platform/rootfs shape, with diff ids rewritten for its own layer set.
    let first = &sources[0];
    let config_bytes = fetch_config_bytes(args, first, plain_http).await?;
    let diff_ids: Vec<String> = data_blobs
        .iter()
        .map(|d| d.digest.clone())
        .chain(std::iter::once(boot_layer.diff_id))
        .collect();
    let config_bytes = rebuild_image_config(&config_bytes, &diff_ids)
        .context("rewrite image config for the chunk dictionary")?;
    let config_digest = retry
        .run("push chunkdict config", || {
            client.push_blob_bytes(&target_ref.repo, &config_bytes)
        })
        .await
        .context("push chunkdict config")?;

    let docker2oci = true;
    let config = Descriptor {
        media_type: config_media_type(docker2oci).to_string(),
        digest: config_digest,
        size: config_bytes.len() as u64,
        annotations: None,
        ..Descriptor::default()
    };
    let manifest = assemble_manifest(docker2oci, config, data_blobs, bootstrap);
    let manifest_bytes = serde_json::to_vec(&manifest).context("serialize chunkdict manifest")?;
    let media_type = manifest_media_type(docker2oci);
    retry
        .run("push chunkdict manifest", || {
            client.push_manifest(
                &target_ref.repo,
                target_ref.manifest_reference(),
                media_type,
                &manifest_bytes,
            )
        })
        .await
        .context("push chunkdict manifest")?;

    info!(
        target = %target_ref,
        blobs = manifest.layers.len() - 1,
        "chunk dictionary published"
    );
    Ok(())
}

/// Fetch the image config blob of a source, to reuse as the dictionary's.
async fn fetch_config_bytes(
    args: &ChunkdictArgs,
    source: &SourceImage,
    plain_http: bool,
) -> Result<Vec<u8>> {
    let client = RegistryClient::new(
        &source.reference.api_host,
        client_options(args.source_insecure, plain_http, &args.ca_cert),
    )
    .context("build source registry client for config")?;
    client
        .get_blob(&source.reference.repo, &source.manifest.config.digest)
        .await
        .with_context(|| {
            format!(
                "fetch image config {} of {}",
                source.manifest.config.digest, source.reference
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_accept_commas_and_repetition() {
        assert_eq!(
            parse_sources(&["a:1,b:2".to_string()]).unwrap(),
            vec!["a:1".to_string(), "b:2".to_string()]
        );
        assert_eq!(
            parse_sources(&["a:1".to_string(), "b:2".to_string()]).unwrap(),
            vec!["a:1".to_string(), "b:2".to_string()]
        );
        // Whitespace around a comma-separated entry is tolerated.
        assert_eq!(
            parse_sources(&["a:1 , b:2".to_string()]).unwrap(),
            vec!["a:1".to_string(), "b:2".to_string()]
        );
    }

    #[test]
    fn sources_reject_empty_entries_and_singletons() {
        assert!(parse_sources(&["a:1,,b:2".to_string()]).is_err());
        // One image cannot share chunks with anything.
        assert!(parse_sources(&["only:1".to_string()]).is_err());
        assert!(parse_sources(&[]).is_err());
    }

    #[test]
    fn staging_dir_lets_the_builder_recover_name_and_tag() {
        // nydus-image splits the directory name on ':' and takes the last two
        // components as image name and tag, so '/' must not survive.
        let dir = staging_dir_name("localhost:5077/redis:7.0.1");
        assert_eq!(dir, "localhost:5077:redis:7.0.1");
        let parts: Vec<&str> = dir.split(':').collect();
        assert_eq!(parts[parts.len() - 2], "redis");
        assert_eq!(parts[parts.len() - 1], "7.0.1");
    }

    #[test]
    fn staging_dir_handles_a_namespaced_repo() {
        // Every path separator becomes ':', so the builder's "last two
        // components" rule lands on the final repo segment and the tag --
        // `ghcr.io/org/team/app:v1` trains as image `app`, tag `v1`.
        let dir = staging_dir_name("ghcr.io/org/team/app:v1");
        assert_eq!(dir, "ghcr.io:org:team:app:v1");
        let parts: Vec<&str> = dir.split(':').collect();
        assert_eq!(parts[parts.len() - 2], "app");
        assert_eq!(parts[parts.len() - 1], "v1");
    }

    #[test]
    fn generate_args_pass_an_absolute_sqlite_url() {
        let args = chunkdict_generate_args(
            Path::new("/w/chunkdict_bootstrap"),
            Path::new("/w"),
            Path::new("/w/out.json"),
            &[PathBuf::from("/w/a/nydus_bootstrap")],
        );
        let strs: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        let db = strs.iter().position(|s| s == "--database").unwrap() + 1;
        // The builder rejects a relative sqlite path.
        assert_eq!(strs[db], "sqlite:///w/database.db");
        assert!(strs.starts_with(&["chunkdict".to_string(), "generate".to_string()]));
        // Source bootstraps are positional and come last.
        assert_eq!(strs.last().unwrap(), "/w/a/nydus_bootstrap");
    }

    #[test]
    fn blob_ids_are_deduplicated_in_order() {
        let ids = dedup_blob_ids(&[
            "bbb".to_string(),
            "aaa".to_string(),
            "bbb".to_string(),
            String::new(),
            "ccc".to_string(),
        ]);
        assert_eq!(ids, vec!["bbb", "aaa", "ccc"]);
    }
}
