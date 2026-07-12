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

use registry_client::Descriptor;
use registry_client::types::{
    MEDIA_TYPE_DOCKER_CONFIG, MEDIA_TYPE_DOCKER_MANIFEST, MEDIA_TYPE_NYDUS_BLOB,
    MEDIA_TYPE_NYDUS_BOOTSTRAP_LAYER, MEDIA_TYPE_OCI_CONFIG, MEDIA_TYPE_OCI_MANIFEST, Manifest,
};

/// Annotation set on nydus data-blob layers so containerd's snapshotter
/// classifies them as [`LayerKind::NydusData`]. Mirrors the snapshotter's
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

#[cfg(test)]
mod tests {
    use super::*;
    use registry_client::types::MEDIA_TYPE_DOCKER_MANIFEST_LIST;

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
}
