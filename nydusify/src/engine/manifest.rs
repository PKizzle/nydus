// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Assembly of the pushed **nydus image manifest** and its media types.
//!
//! The produced manifest matches what the Go nydusify emits and what the Rust
//! snapshotter consumes (see `snapshotter/src/source/labels.rs`):
//!
//! * `config`  — the (reused) image config, media type per `docker2oci`.
//! * `layers`  — every nydus data blob (`...layer.nydus.blob.v1`, annotated
//!   `containerd.io/snapshot/nydus-blob`), followed by the RAFS bootstrap layer
//!   (`...layer.nydus.bootstrap.v1`, annotated
//!   `containerd.io/snapshot/nydus-bootstrap`) LAST.
//!
//! Media types follow `docker2oci`: OCI when `true`, docker schema-2 when
//! `false`. The nydus blob/bootstrap layer media types are the same in both
//! (there is no docker-namespaced nydus media type).

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use registry_client::Descriptor;
use registry_client::types::{
    History, ImageConfig, Index, MEDIA_TYPE_DOCKER_CONFIG, MEDIA_TYPE_DOCKER_MANIFEST,
    MEDIA_TYPE_DOCKER_MANIFEST_LIST, MEDIA_TYPE_NYDUS_BLOB, MEDIA_TYPE_NYDUS_BOOTSTRAP_LAYER,
    MEDIA_TYPE_OCI_CONFIG, MEDIA_TYPE_OCI_INDEX, MEDIA_TYPE_OCI_MANIFEST, Manifest,
};

/// Annotation set on nydus data-blob layers so containerd's snapshotter
/// classifies them as `LayerKind::NydusData`. Mirrors the snapshotter's
/// `NYDUS_DATA_LAYER` label.
pub const ANNOTATION_NYDUS_DATA: &str = "containerd.io/snapshot/nydus-blob";
/// Annotation set on the nydus bootstrap layer. Mirrors the snapshotter's
/// `NYDUS_META_LAYER` label (`registry_client::types::ANNOTATION_NYDUS_BOOTSTRAP`).
pub const ANNOTATION_NYDUS_BOOTSTRAP: &str = "containerd.io/snapshot/nydus-bootstrap";

/// The manifest media type to publish under, per `docker2oci`.
pub fn manifest_media_type(docker2oci: bool) -> &'static str {
    if docker2oci {
        MEDIA_TYPE_OCI_MANIFEST
    } else {
        MEDIA_TYPE_DOCKER_MANIFEST
    }
}

/// The config-descriptor media type to publish under, per `docker2oci`.
pub fn config_media_type(docker2oci: bool) -> &'static str {
    if docker2oci {
        MEDIA_TYPE_OCI_CONFIG
    } else {
        MEDIA_TYPE_DOCKER_CONFIG
    }
}

/// Build a nydus **data-blob** layer descriptor (annotated `nydus-blob`).
pub fn data_blob_descriptor(digest: String, size: u64) -> Descriptor {
    Descriptor {
        media_type: MEDIA_TYPE_NYDUS_BLOB.to_string(),
        digest,
        size,
        annotations: Some(BTreeMap::from([(
            ANNOTATION_NYDUS_DATA.to_string(),
            "true".to_string(),
        )])),
        ..Descriptor::default()
    }
}

/// Build the nydus **bootstrap** layer descriptor (annotated `nydus-bootstrap`).
pub fn bootstrap_descriptor(digest: String, size: u64) -> Descriptor {
    Descriptor {
        media_type: MEDIA_TYPE_NYDUS_BOOTSTRAP_LAYER.to_string(),
        digest,
        size,
        annotations: Some(BTreeMap::from([(
            ANNOTATION_NYDUS_BOOTSTRAP.to_string(),
            "true".to_string(),
        )])),
        ..Descriptor::default()
    }
}

/// `created_by` recorded on the appended bootstrap-layer history entry.
/// Mirrors the Go nydus converter (`pkg/converter/convert_unix.go`).
pub const BOOTSTRAP_HISTORY_CREATED_BY: &str = "Nydus Converter";
/// `comment` recorded on the appended bootstrap-layer history entry.
pub const BOOTSTRAP_HISTORY_COMMENT: &str = "Nydus Bootstrap Layer";

/// Rebuild the source image config so its `rootfs.diff_ids` matches the nydus
/// image's new layer set exactly.
///
/// containerd's image unpacker requires
/// `len(config.rootfs.diff_ids) == len(manifest.layers)` (else it fails with
/// "mismatched image rootfs and manifest layers"). The convert pipeline
/// replaces the original gzip layers with nydus data blobs + a bootstrap, so
/// the reused config's original diff_ids no longer match. This rewrites them.
///
/// `layer_digests` are the digests of the pushed manifest layers, in order
/// (data blobs first, bootstrap last). Following the Go converter
/// (`makeNewConfig` in `pkg/converter/convert_unix.go`), for the registry
/// (no-backend) case each layer's diff_id is set to the layer's own
/// `LayerAnnotationUncompressed` value — which for nydus data blobs and an
/// uncompressed bootstrap equals the layer's own content digest. A single
/// bootstrap history entry is appended (original history is preserved).
pub fn rebuild_image_config(config_bytes: &[u8], layer_digests: &[String]) -> Result<Vec<u8>> {
    let mut config: ImageConfig =
        serde_json::from_slice(config_bytes).context("parse source image config JSON")?;

    if config.rootfs.type_.is_empty() {
        config.rootfs.type_ = "layers".to_string();
    }
    config.rootfs.diff_ids = layer_digests.to_vec();

    config.history.push(History {
        created_by: Some(BOOTSTRAP_HISTORY_CREATED_BY.to_string()),
        comment: Some(BOOTSTRAP_HISTORY_COMMENT.to_string()),
        ..History::default()
    });

    serde_json::to_vec(&config).context("serialize rewritten nydus image config")
}

/// Assemble the nydus image [`Manifest`] from an already-pushed config
/// descriptor, the data-blob descriptors (in device-table order, lower→upper),
/// and the bootstrap descriptor (appended last).
pub fn assemble_manifest(
    docker2oci: bool,
    config: Descriptor,
    data_blobs: Vec<Descriptor>,
    bootstrap: Descriptor,
) -> Manifest {
    let mut layers = data_blobs;
    layers.push(bootstrap);
    Manifest {
        schema_version: 2,
        media_type: Some(manifest_media_type(docker2oci).to_string()),
        artifact_type: None,
        config,
        layers,
        subject: None,
        annotations: None,
    }
}

/// Assemble a multi-platform OCI image **index** from the per-platform nydus
/// manifest descriptors (each must carry its `platform`). The index media type
/// follows `docker2oci` so a docker-schema conversion still produces a docker
/// manifest list. Callers push the per-platform manifests by digest first,
/// then push this index at the target tag.
pub fn assemble_index(docker2oci: bool, manifests: Vec<Descriptor>) -> Index {
    Index {
        schema_version: 2,
        media_type: Some(index_media_type(docker2oci).to_string()),
        manifests,
        annotations: None,
    }
}

/// The image-index / manifest-list media type to publish under, per `docker2oci`.
pub fn index_media_type(docker2oci: bool) -> &'static str {
    if docker2oci {
        MEDIA_TYPE_OCI_INDEX
    } else {
        MEDIA_TYPE_DOCKER_MANIFEST_LIST
    }
}

/// Locate the nydus bootstrap layer in a (pulled) nydus image manifest.
///
/// Prefers a layer annotated `containerd.io/snapshot/nydus-bootstrap = "true"`
/// (the canonical marker both the Go and Rust nydusify emit and the snapshotter
/// keys on), falling back to a layer whose media type names a nydus bootstrap
/// (`...bootstrap.nydus...` / `...nydus.bootstrap...`).
pub fn find_bootstrap_layer(manifest: &Manifest) -> Option<&Descriptor> {
    manifest
        .layers
        .iter()
        .find(|layer| {
            layer
                .annotations
                .as_ref()
                .and_then(|a| a.get(ANNOTATION_NYDUS_BOOTSTRAP))
                .map(|v| v == "true")
                .unwrap_or(false)
        })
        .or_else(|| {
            manifest.layers.iter().find(|layer| {
                let m = &layer.media_type;
                m.contains("bootstrap") && m.contains("nydus")
            })
        })
}

/// Whether `layer` is a nydus data-blob layer (media type
/// `...layer.nydus.blob.v1` or the `nydus-blob` annotation).
fn is_nydus_data_layer(layer: &Descriptor) -> bool {
    layer.media_type == MEDIA_TYPE_NYDUS_BLOB
        || layer
            .annotations
            .as_ref()
            .and_then(|a| a.get(ANNOTATION_NYDUS_DATA))
            .map(|v| v == "true")
            .unwrap_or(false)
}

/// Validate that `manifest` describes a nydus image: it must carry a bootstrap
/// layer and at least one nydus data-blob layer. Returns the bootstrap
/// descriptor so the caller can download and inspect it.
pub fn validate_nydus_manifest(manifest: &Manifest) -> Result<&Descriptor> {
    if manifest.layers.is_empty() {
        bail!("manifest has no layers; not a nydus image");
    }
    let bootstrap = find_bootstrap_layer(manifest).ok_or_else(|| {
        anyhow!(
            "no nydus bootstrap layer found (expected a layer annotated \
             {ANNOTATION_NYDUS_BOOTSTRAP}=true or a *.bootstrap.nydus.* media type)"
        )
    })?;
    if !manifest.layers.iter().any(is_nydus_data_layer) {
        bail!(
            "manifest has a bootstrap layer but no nydus data-blob layer \
             ({MEDIA_TYPE_NYDUS_BLOB}); not a valid nydus image"
        );
    }
    Ok(bootstrap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_client::types::{MEDIA_TYPE_DOCKER_MANIFEST_LIST, MEDIA_TYPE_OCI_LAYER_TAR_GZIP};

    #[test]
    fn media_types_switch_on_docker2oci() {
        assert_eq!(manifest_media_type(true), MEDIA_TYPE_OCI_MANIFEST);
        assert_eq!(manifest_media_type(false), MEDIA_TYPE_DOCKER_MANIFEST);
        assert_eq!(config_media_type(true), MEDIA_TYPE_OCI_CONFIG);
        assert_eq!(config_media_type(false), MEDIA_TYPE_DOCKER_CONFIG);
        // Manifest media type is never a manifest-list/index type.
        assert_ne!(manifest_media_type(false), MEDIA_TYPE_DOCKER_MANIFEST_LIST);
    }

    #[test]
    fn assemble_index_carries_platforms_and_switches_media_type() {
        use registry_client::types::{MEDIA_TYPE_OCI_INDEX, Platform};
        let leaf = |arch: &str| Descriptor {
            media_type: MEDIA_TYPE_OCI_MANIFEST.to_string(),
            digest: format!("sha256:{arch}"),
            size: 10,
            platform: Some(Platform {
                architecture: arch.to_string(),
                os: "linux".to_string(),
                ..Default::default()
            }),
            ..Descriptor::default()
        };
        let oci = assemble_index(true, vec![leaf("amd64"), leaf("arm64")]);
        assert_eq!(oci.media_type.as_deref(), Some(MEDIA_TYPE_OCI_INDEX));
        assert_eq!(oci.manifests.len(), 2);
        assert_eq!(
            oci.manifests[1].platform.as_ref().unwrap().architecture,
            "arm64"
        );
        // A round-trip serialization keeps the index parseable.
        let bytes = serde_json::to_vec(&oci).unwrap();
        let back: registry_client::types::Index = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.manifests.len(), 2);

        // docker2oci=false publishes a docker manifest list.
        let docker = assemble_index(false, vec![leaf("amd64")]);
        assert_eq!(
            docker.media_type.as_deref(),
            Some(MEDIA_TYPE_DOCKER_MANIFEST_LIST)
        );
    }

    #[test]
    fn data_and_bootstrap_descriptors_are_annotated() {
        let data = data_blob_descriptor("sha256:d".into(), 10);
        assert_eq!(data.media_type, MEDIA_TYPE_NYDUS_BLOB);
        assert_eq!(
            data.annotations
                .unwrap()
                .get(ANNOTATION_NYDUS_DATA)
                .unwrap(),
            "true"
        );
        let boot = bootstrap_descriptor("sha256:b".into(), 20);
        assert_eq!(boot.media_type, MEDIA_TYPE_NYDUS_BOOTSTRAP_LAYER);
        assert_eq!(
            boot.annotations
                .unwrap()
                .get(ANNOTATION_NYDUS_BOOTSTRAP)
                .unwrap(),
            "true"
        );
    }

    #[test]
    fn assemble_puts_bootstrap_last_and_preserves_blob_order() {
        let config = Descriptor::for_bytes(MEDIA_TYPE_OCI_CONFIG, b"{}");
        let d0 = data_blob_descriptor("sha256:0".into(), 1);
        let d1 = data_blob_descriptor("sha256:1".into(), 2);
        let boot = bootstrap_descriptor("sha256:boot".into(), 3);
        let manifest = assemble_manifest(true, config, vec![d0, d1], boot);

        assert_eq!(manifest.schema_version, 2);
        assert_eq!(
            manifest.media_type.as_deref(),
            Some(MEDIA_TYPE_OCI_MANIFEST)
        );
        assert_eq!(manifest.layers.len(), 3);
        assert_eq!(manifest.layers[0].digest, "sha256:0");
        assert_eq!(manifest.layers[1].digest, "sha256:1");
        // Bootstrap is last and carries the meta annotation.
        let last = manifest.layers.last().unwrap();
        assert_eq!(last.media_type, MEDIA_TYPE_NYDUS_BOOTSTRAP_LAYER);
        assert!(
            last.annotations
                .as_ref()
                .unwrap()
                .contains_key(ANNOTATION_NYDUS_BOOTSTRAP)
        );

        // Round-trips through serde as a valid OCI manifest.
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let reparsed: Manifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reparsed, manifest);
        assert!(reparsed.subject.is_none());
    }

    fn nydus_manifest() -> Manifest {
        let config = Descriptor::for_bytes(MEDIA_TYPE_OCI_CONFIG, b"{}");
        let data = data_blob_descriptor("sha256:data".into(), 100);
        let boot = bootstrap_descriptor("sha256:boot".into(), 50);
        assemble_manifest(true, config, vec![data], boot)
    }

    #[test]
    fn finds_bootstrap_by_annotation() {
        let manifest = nydus_manifest();
        let bootstrap = find_bootstrap_layer(&manifest).unwrap();
        assert_eq!(bootstrap.digest, "sha256:boot");
    }

    #[test]
    fn finds_bootstrap_by_media_type_without_annotation() {
        // A bootstrap layer identified only by media type (no annotation).
        let mut manifest = nydus_manifest();
        let boot = manifest.layers.last_mut().unwrap();
        boot.annotations = None;
        boot.media_type = "application/vnd.oci.image.bootstrap.nydus.v1".to_string();
        let bootstrap = find_bootstrap_layer(&manifest).unwrap();
        assert_eq!(bootstrap.digest, "sha256:boot");
    }

    #[test]
    fn validate_accepts_a_nydus_manifest_and_returns_bootstrap() {
        let manifest = nydus_manifest();
        let bootstrap = validate_nydus_manifest(&manifest).unwrap();
        assert_eq!(bootstrap.digest, "sha256:boot");
    }

    #[test]
    fn validate_rejects_a_plain_oci_manifest() {
        // A standard OCI image: gzip layers, no nydus bootstrap.
        let mut manifest = nydus_manifest();
        for layer in &mut manifest.layers {
            layer.media_type = MEDIA_TYPE_OCI_LAYER_TAR_GZIP.to_string();
            layer.annotations = None;
        }
        let err = validate_nydus_manifest(&manifest).unwrap_err();
        assert!(err.to_string().contains("no nydus bootstrap layer"));
    }

    /// A synthetic source image config with `n` original gzip diff_ids and one
    /// history entry per layer.
    fn source_config_json(n: usize) -> Vec<u8> {
        let diff_ids: Vec<String> = (0..n).map(|i| format!("sha256:orig{i}")).collect();
        let history: Vec<serde_json::Value> = (0..n)
            .map(|i| serde_json::json!({ "created_by": format!("RUN step {i}") }))
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "config": { "Env": ["PATH=/usr/bin"], "Cmd": ["/bin/sh"] },
            "rootfs": { "type": "layers", "diff_ids": diff_ids },
            "history": history,
        }))
        .unwrap()
    }

    fn parse_config(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap()
    }

    #[test]
    fn rebuild_config_standard_mode_diffids_match_layer_count() {
        // Standard mode: N new nydus data blobs + 1 bootstrap => N+1 layers.
        let n = 3;
        let source = source_config_json(n);

        let mut data_blobs = Vec::new();
        for i in 0..n {
            data_blobs.push(data_blob_descriptor(format!("sha256:nydus{i}"), 100));
        }
        let bootstrap = bootstrap_descriptor("sha256:boot".into(), 50);

        let layer_digests: Vec<String> = data_blobs
            .iter()
            .chain(std::iter::once(&bootstrap))
            .map(|d| d.digest.clone())
            .collect();

        let new_config = rebuild_image_config(&source, &layer_digests).unwrap();
        let config = Descriptor::for_bytes(MEDIA_TYPE_OCI_CONFIG, &new_config);
        let manifest = assemble_manifest(true, config, data_blobs, bootstrap);

        let parsed = parse_config(&new_config);
        let diff_ids = parsed["rootfs"]["diff_ids"].as_array().unwrap();

        // The core invariant containerd enforces.
        assert_eq!(diff_ids.len(), manifest.layers.len());
        assert_eq!(diff_ids.len(), n + 1);
        // diff_ids are, in order, exactly the pushed layer digests.
        for (diff_id, layer) in diff_ids.iter().zip(&manifest.layers) {
            assert_eq!(diff_id.as_str().unwrap(), layer.digest);
        }
        // Original config fields survive the rewrite.
        assert_eq!(parsed["architecture"], "amd64");
        assert_eq!(parsed["config"]["Cmd"][0], "/bin/sh");
        // One bootstrap history entry appended after the originals.
        let history = parsed["history"].as_array().unwrap();
        assert_eq!(history.len(), n + 1);
        let last = history.last().unwrap();
        assert_eq!(last["created_by"], BOOTSTRAP_HISTORY_CREATED_BY);
        assert_eq!(last["comment"], BOOTSTRAP_HISTORY_COMMENT);
    }

    #[test]
    fn rebuild_config_oci_ref_mode_diffids_match_layer_count() {
        // oci-ref/zran mode: N reused gzip layers + N zran-index blobs + 1
        // bootstrap => 2N+1 layers. diff_ids must still match exactly.
        let n = 2;
        let source = source_config_json(n);

        let mut data_blobs = Vec::new();
        for i in 0..n {
            // Reused original gzip layer (its own digest is the nydus blob id).
            data_blobs.push(data_blob_descriptor(format!("sha256:orig{i}"), 900));
        }
        for i in 0..n {
            // Tiny per-layer zran index blob.
            data_blobs.push(data_blob_descriptor(format!("sha256:zran{i}"), 20));
        }
        let bootstrap = bootstrap_descriptor("sha256:boot".into(), 50);

        let layer_digests: Vec<String> = data_blobs
            .iter()
            .chain(std::iter::once(&bootstrap))
            .map(|d| d.digest.clone())
            .collect();

        let new_config = rebuild_image_config(&source, &layer_digests).unwrap();
        let config = Descriptor::for_bytes(MEDIA_TYPE_OCI_CONFIG, &new_config);
        let manifest = assemble_manifest(true, config, data_blobs, bootstrap);

        let parsed = parse_config(&new_config);
        let diff_ids = parsed["rootfs"]["diff_ids"].as_array().unwrap();

        assert_eq!(diff_ids.len(), manifest.layers.len());
        assert_eq!(diff_ids.len(), 2 * n + 1);
        for (diff_id, layer) in diff_ids.iter().zip(&manifest.layers) {
            assert_eq!(diff_id.as_str().unwrap(), layer.digest);
        }
    }

    #[test]
    fn rebuild_config_defaults_rootfs_type_when_absent() {
        let source = serde_json::to_vec(&serde_json::json!({
            "architecture": "arm64",
            "os": "linux",
        }))
        .unwrap();
        let layer_digests = vec!["sha256:a".to_string(), "sha256:boot".to_string()];
        let new_config = rebuild_image_config(&source, &layer_digests).unwrap();
        let parsed = parse_config(&new_config);
        assert_eq!(parsed["rootfs"]["type"], "layers");
        assert_eq!(parsed["rootfs"]["diff_ids"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn validate_rejects_bootstrap_without_data_blob() {
        let config = Descriptor::for_bytes(MEDIA_TYPE_OCI_CONFIG, b"{}");
        let boot = bootstrap_descriptor("sha256:boot".into(), 50);
        // Only a bootstrap layer, no data blob.
        let manifest = Manifest {
            schema_version: 2,
            media_type: Some(MEDIA_TYPE_OCI_MANIFEST.to_string()),
            artifact_type: None,
            config,
            layers: vec![boot],
            subject: None,
            annotations: None,
        };
        let err = validate_nydus_manifest(&manifest).unwrap_err();
        assert!(err.to_string().contains("no nydus data-blob layer"));
    }
}
