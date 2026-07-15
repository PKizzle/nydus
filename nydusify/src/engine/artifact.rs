// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Referrer-artifact push.
//!
//! Transparent node-local acceleration never pushes a referrer, but the
//! registry-publish flow (`nydusify convert --with-referrer`) attaches the
//! pushed nydus artifact to the *source* image as an OCI 1.1 referrer:
//!
//! * `artifactType` = `application/vnd.oci.image.layer.nydus.blob.v1`.
//! * `config`       = the empty artifact config (`{}`).
//! * `layers`       = the nydus data blobs (`...layer.nydus.blob.v1`) followed by
//!   the bootstrap layer (`...bootstrap.nydus.v1`, annotated
//!   `containerd.io/snapshot/nydus-bootstrap = "true"`).
//! * `subject`      = the descriptor of the *source* image manifest captured at
//!   pull time.
//!
//! The artifact + its referenced blobs are pushed to the **source repo** so the
//! referrer resolves alongside its subject (this is why the blobs are re-pushed
//! there; `HEAD`-dedup makes it free when the source and target repos coincide,
//! and for `--oci-ref` the reused gzip layers are already present). It is
//! published both by digest (registries with native referrers-API support build
//! the referrers index from the `subject`) and under the `sha256-<subject-hex>`
//! **fallback tag** (the referrers-API fallback for registries such as Zot /
//! older Harbor that lack native support).
//!
//! The exact manifest shape mirrors what the snapshotter consumes
//! (`snapshotter/src/source/referrer.rs::classify_descriptor` +
//! `misc/fanotify/b4b-referrer-serving-test.sh`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use registry_client::types::{
    ANNOTATION_NYDUS_BOOTSTRAP, MEDIA_TYPE_NYDUS_BLOB, MEDIA_TYPE_NYDUS_BOOTSTRAP,
    MEDIA_TYPE_OCI_CONFIG, MEDIA_TYPE_OCI_MANIFEST, Manifest,
};
use registry_client::{Descriptor, RegistryClient};
use tracing::info;

use crate::engine::retry::RetryPolicy;

/// The referrer artifact's `artifactType`: the nydus data-blob media type. This
/// is the value the snapshotter matches on ("nydus" substring) when classifying
/// an artifact descriptor.
pub const REFERRER_ARTIFACT_TYPE: &str = MEDIA_TYPE_NYDUS_BLOB;

/// The empty artifact config body (`{}`), pushed as the referrer manifest's
/// `config` blob.
pub const REFERRER_CONFIG_BYTES: &[u8] = b"{}";

/// Push the nydus artifact as an OCI referrer of the source image. Called
/// after the nydus image manifest has been pushed.
///
/// * `with_referrer` — the `--with-referrer` flag; when unset this is a no-op
///   and returns `Ok(None)`.
/// * `source_client` / `source_repo` — where the referrer (and its blobs) live,
///   alongside the subject.
/// * `data_blob_files` — the nydus data-blob files, in image-layer order (the
///   reused gzip layers then the newly-built blobs).
/// * `bootstrap_file` — the merged RAFS bootstrap file.
/// * `subject` — descriptor of the source image manifest; becomes the
///   referrer artifact's `subject`.
/// * `retry` — retry policy applied to each idempotent push.
///
/// Returns the pushed artifact descriptor on success.
pub async fn maybe_push_referrer(
    with_referrer: bool,
    source_client: &RegistryClient,
    source_repo: &str,
    data_blob_files: &[PathBuf],
    bootstrap_file: &Path,
    subject: &Descriptor,
    retry: &RetryPolicy,
) -> Result<Option<Descriptor>> {
    if !with_referrer {
        return Ok(None);
    }

    // Referrers must resolve alongside their subject, so every blob the artifact
    // references has to exist in the source repo. push_blob_file HEAD-dedups, so
    // this is free when the target repo == source repo (or, for --oci-ref, for
    // the original gzip layers that already live here).
    let mut data_blobs = Vec::with_capacity(data_blob_files.len());
    for file in data_blob_files {
        let digest = retry
            .run("push referrer data blob", || {
                source_client.push_blob_file(source_repo, file)
            })
            .await
            .with_context(|| format!("push referrer data blob {}", file.display()))?;
        data_blobs.push(referrer_data_blob_descriptor(digest, file_len(file)?));
    }

    let boot_digest = retry
        .run("push referrer bootstrap", || {
            source_client.push_blob_file(source_repo, bootstrap_file)
        })
        .await
        .context("push referrer bootstrap blob")?;
    let bootstrap = referrer_bootstrap_descriptor(boot_digest, file_len(bootstrap_file)?);

    let config_digest = retry
        .run("push referrer config", || {
            source_client.push_blob_bytes(source_repo, REFERRER_CONFIG_BYTES)
        })
        .await
        .context("push referrer artifact config")?;
    let config = Descriptor {
        media_type: MEDIA_TYPE_OCI_CONFIG.to_string(),
        digest: config_digest,
        size: REFERRER_CONFIG_BYTES.len() as u64,
        ..Descriptor::default()
    };

    let manifest = build_referrer_manifest(config, data_blobs, bootstrap, subject.clone());
    let bytes = serde_json::to_vec(&manifest).context("serialize referrer artifact manifest")?;
    let artifact = Descriptor::for_bytes(MEDIA_TYPE_OCI_MANIFEST, &bytes);

    // (1) By digest: registries with native referrers-API support index this via
    // the subject; the immutable digest is the canonical address.
    retry
        .run("push referrer manifest", || {
            source_client.push_manifest(
                source_repo,
                &artifact.digest,
                MEDIA_TYPE_OCI_MANIFEST,
                &bytes,
            )
        })
        .await
        .context("push referrer artifact manifest by digest")?;
    // (2) Fallback tag: the referrers-API fallback for registries without native
    // support — the snapshotter GETs `sha256-<subject-hex>` when /referrers 404s.
    let fallback = fallback_referrers_tag(&subject.digest);
    retry
        .run("push referrer fallback tag", || {
            source_client.push_manifest(source_repo, &fallback, MEDIA_TYPE_OCI_MANIFEST, &bytes)
        })
        .await
        .with_context(|| format!("push referrer fallback tag {fallback}"))?;

    info!(
        repo = %source_repo,
        artifact = %artifact.digest,
        subject = %subject.digest,
        fallback_tag = %fallback,
        "pushed nydus referrer artifact"
    );
    Ok(Some(artifact))
}

/// The referrers-API fallback tag for a subject digest: `sha256:<hex>` becomes
/// `sha256-<hex>`. Must match the snapshotter's `fallback_referrers_tag`
/// (`snapshotter/src/source/referrer.rs`).
pub fn fallback_referrers_tag(subject_digest: &str) -> String {
    subject_digest.replace(':', "-")
}

/// A referrer data-blob layer descriptor (`...layer.nydus.blob.v1`, no
/// annotations).
pub fn referrer_data_blob_descriptor(digest: String, size: u64) -> Descriptor {
    Descriptor {
        media_type: MEDIA_TYPE_NYDUS_BLOB.to_string(),
        digest,
        size,
        ..Descriptor::default()
    }
}

/// The referrer bootstrap-layer descriptor (`...bootstrap.nydus.v1`, annotated
/// `containerd.io/snapshot/nydus-bootstrap = "true"`). The snapshotter keys on
/// this annotation to locate the bootstrap.
pub fn referrer_bootstrap_descriptor(digest: String, size: u64) -> Descriptor {
    Descriptor {
        media_type: MEDIA_TYPE_NYDUS_BOOTSTRAP.to_string(),
        digest,
        size,
        annotations: Some(BTreeMap::from([(
            ANNOTATION_NYDUS_BOOTSTRAP.to_string(),
            "true".to_string(),
        )])),
        ..Descriptor::default()
    }
}

/// Assemble the referrer artifact [`Manifest`]: `artifactType` set, data blobs
/// first, bootstrap last, `subject` present.
pub fn build_referrer_manifest(
    config: Descriptor,
    data_blobs: Vec<Descriptor>,
    bootstrap: Descriptor,
    subject: Descriptor,
) -> Manifest {
    let mut layers = data_blobs;
    layers.push(bootstrap);
    Manifest {
        schema_version: 2,
        media_type: Some(MEDIA_TYPE_OCI_MANIFEST.to_string()),
        artifact_type: Some(REFERRER_ARTIFACT_TYPE.to_string()),
        config,
        layers,
        subject: Some(subject),
        annotations: None,
    }
}

fn file_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_client::types::MEDIA_TYPE_OCI_MANIFEST;

    fn subject_desc() -> Descriptor {
        Descriptor {
            media_type: MEDIA_TYPE_OCI_MANIFEST.to_string(),
            digest: "sha256:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a94a8fe5ccb19ba61c4c0873"
                .to_string(),
            size: 1024,
            ..Descriptor::default()
        }
    }

    #[test]
    fn fallback_tag_replaces_colon_with_dash() {
        assert_eq!(fallback_referrers_tag("sha256:deadbeef"), "sha256-deadbeef");
        // Derived from the SUBJECT digest, not the artifact digest.
        assert_eq!(
            fallback_referrers_tag(&subject_desc().digest),
            "sha256-a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a94a8fe5ccb19ba61c4c0873"
        );
    }

    #[test]
    fn referrer_manifest_matches_the_consumed_shape() {
        let config = Descriptor::for_bytes(MEDIA_TYPE_OCI_CONFIG, REFERRER_CONFIG_BYTES);
        let d0 = referrer_data_blob_descriptor("sha256:d0".into(), 10);
        let d1 = referrer_data_blob_descriptor("sha256:d1".into(), 20);
        let boot = referrer_bootstrap_descriptor("sha256:boot".into(), 30);
        let manifest = build_referrer_manifest(config, vec![d0, d1], boot, subject_desc());

        // artifactType is the nydus blob media type.
        assert_eq!(
            manifest.artifact_type.as_deref(),
            Some(MEDIA_TYPE_NYDUS_BLOB)
        );
        assert_eq!(
            manifest.media_type.as_deref(),
            Some(MEDIA_TYPE_OCI_MANIFEST)
        );
        // Empty config body.
        assert_eq!(manifest.config.media_type, MEDIA_TYPE_OCI_CONFIG);
        assert_eq!(manifest.config.size, 2);

        // Layer ordering: data blobs first, bootstrap LAST.
        assert_eq!(manifest.layers.len(), 3);
        assert_eq!(manifest.layers[0].digest, "sha256:d0");
        assert_eq!(manifest.layers[0].media_type, MEDIA_TYPE_NYDUS_BLOB);
        assert!(manifest.layers[0].annotations.is_none());
        assert_eq!(manifest.layers[1].digest, "sha256:d1");

        // Bootstrap: correct media type + the nydus-bootstrap annotation.
        let bootstrap = manifest.layers.last().unwrap();
        assert_eq!(bootstrap.media_type, MEDIA_TYPE_NYDUS_BOOTSTRAP);
        assert_eq!(
            bootstrap
                .annotations
                .as_ref()
                .unwrap()
                .get(ANNOTATION_NYDUS_BOOTSTRAP)
                .map(String::as_str),
            Some("true")
        );

        // Subject is present and is the source manifest descriptor.
        let subject = manifest.subject.as_ref().unwrap();
        assert_eq!(subject.digest, subject_desc().digest);
        assert_eq!(subject.media_type, MEDIA_TYPE_OCI_MANIFEST);

        // Round-trips through serde as a valid OCI manifest with camelCase keys.
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let reparsed: Manifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reparsed, manifest);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\"artifactType\""));
        assert!(text.contains("\"subject\""));
    }

    #[test]
    fn no_op_when_flag_unset() {
        // With the flag unset the call must not touch the network; a client
        // pointed at an unroutable host proves nothing is sent.
        //
        // `RegistryClient::new` must run INSIDE the compio runtime: when the
        // workspace unifies cyper's `hickory-dns` feature (nydus-storage
        // enables it), building a client constructs the Hickory resolver via
        // `Runtime::current()`. Production matches — `#[compio::main]` wraps
        // every construction site — so the test does too.
        let result = compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                let client = RegistryClient::new(
                    "registry.invalid:5000",
                    registry_client::RegistryClientOptions {
                        use_docker_config: false,
                        ..Default::default()
                    },
                )
                .unwrap();
                let subject = subject_desc();
                let retry = RetryPolicy::default();
                maybe_push_referrer(
                    false,
                    &client,
                    "team/app",
                    &[],
                    Path::new("/x"),
                    &subject,
                    &retry,
                )
                .await
            })
            .unwrap();
        assert!(result.is_none());
    }
}
