// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! OCI image-manifest wrapper for the auto-accel sidecar.
//!
//! The producer emits a minimal OCI image manifest whose `config` is the
//! existing `AutoAccelManifest` JSON (the source of truth for the
//! sidecar's structure and subject pinning) and whose `layers[]` cover
//! the bootstrap + per-layer zran indexes + optional prefetch blob. The
//! whole point of this wrapping is to make `ctr image pull
//! <synthetic-ref>` work: containerd treats the manifest as a real OCI
//! image, walks `config` + `layers[]`, and pulls every blob through
//! `registries.yaml`'s mirror chain (k3s's embedded spegel) by digest.
//! Without that wrapping a peer that pulls the synthetic ref gets the
//! manifest blob only — bootstrap/indexes/prefetch sit at the producer
//! and the consumer fails to stage the backend dir.
//!
//! Types live here rather than in `auto_zran.rs` so the producer
//! (`auto_zran::run_conversion`) and the consumer (`auto_accel_sidecar::
//! SidecarLocator::resolve_or_pull`) parse the same wire schema from a
//! single definition.

use crate::auto_zran::{AutoAccelDescriptor, AutoAccelLayerDescriptor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimal OCI image manifest schema.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OciImageManifest {
    pub schema_version: u32,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OciDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

pub const OCI_MANIFEST_MEDIATYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const AUTO_ACCEL_CONFIG_MEDIATYPE: &str = "application/vnd.nydus.auto-accel.config.v1+json";
pub const AUTO_ACCEL_BOOTSTRAP_MEDIATYPE: &str = "application/vnd.nydus.auto-accel.bootstrap.v1";
pub const AUTO_ACCEL_INDEX_MEDIATYPE: &str = "application/vnd.nydus.auto-accel.zran-index.v1";
pub const AUTO_ACCEL_PREFETCH_MEDIATYPE: &str = "application/vnd.nydus.auto-accel.prefetch-blob.v1";
pub const AUTO_ACCEL_SUBJECT_ANNOTATION: &str = "containerd.io/snapshot/nydus.auto-accel.subject";
pub const AUTO_ACCEL_LAYER_DIGEST_ANNOTATION: &str =
    "containerd.io/snapshot/nydus.auto-accel.layer-digest";

/// Inputs for assembling the OCI image manifest from already-uploaded
/// blobs. Pulled out into a struct so the producer code stays linear and
/// the helper can be unit-tested directly without an in-flight conversion.
pub struct OciManifestInputs<'a> {
    pub subject_manifest_digest: &'a str,
    pub config_digest: &'a str,
    pub config_size: u64,
    pub bootstrap: &'a AutoAccelDescriptor,
    pub zran_indexes: &'a [AutoAccelLayerDescriptor],
    pub prefetch_blob: Option<&'a AutoAccelDescriptor>,
}

/// Assemble the OCI image manifest. Caller commits its serialised bytes
/// as a content blob and registers the resulting digest under the
/// synthetic image name. Pure function so unit tests can pin the wire
/// schema without mocking the content-store client.
pub fn build_oci_manifest(inputs: &OciManifestInputs<'_>) -> OciImageManifest {
    let mut layers = Vec::with_capacity(1 + inputs.zran_indexes.len() + 1);
    layers.push(OciDescriptor {
        media_type: AUTO_ACCEL_BOOTSTRAP_MEDIATYPE.to_string(),
        digest: inputs.bootstrap.digest.clone(),
        size: inputs.bootstrap.size,
        annotations: HashMap::new(),
    });
    for index in inputs.zran_indexes {
        let mut anns = HashMap::new();
        anns.insert(
            AUTO_ACCEL_LAYER_DIGEST_ANNOTATION.to_string(),
            index.layer_digest.clone(),
        );
        layers.push(OciDescriptor {
            media_type: AUTO_ACCEL_INDEX_MEDIATYPE.to_string(),
            digest: index.digest.clone(),
            size: index.size,
            annotations: anns,
        });
    }
    if let Some(pf) = inputs.prefetch_blob {
        layers.push(OciDescriptor {
            media_type: AUTO_ACCEL_PREFETCH_MEDIATYPE.to_string(),
            digest: pf.digest.clone(),
            size: pf.size,
            annotations: HashMap::new(),
        });
    }
    let mut manifest_annotations = HashMap::new();
    manifest_annotations.insert(
        AUTO_ACCEL_SUBJECT_ANNOTATION.to_string(),
        inputs.subject_manifest_digest.to_string(),
    );
    OciImageManifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIATYPE.to_string(),
        config: OciDescriptor {
            media_type: AUTO_ACCEL_CONFIG_MEDIATYPE.to_string(),
            digest: inputs.config_digest.to_string(),
            size: inputs.config_size,
            annotations: HashMap::new(),
        },
        layers,
        annotations: manifest_annotations,
    }
}

// `AutoAccelManifest` lives in `auto_zran` because the producer-facing
// API still uses it directly. Consumers `use crate::auto_zran::AutoAccelManifest`
// alongside `auto_accel_oci::*`.

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_descriptor(d: &str, size: u64) -> AutoAccelDescriptor {
        AutoAccelDescriptor {
            digest: d.to_string(),
            size,
        }
    }

    fn fixture_index(layer: &str, idx: &str, size: u64) -> AutoAccelLayerDescriptor {
        AutoAccelLayerDescriptor {
            layer_digest: layer.to_string(),
            digest: idx.to_string(),
            size,
        }
    }

    #[test]
    fn manifest_media_types_match_oci_spec_and_nydus_conventions() {
        let bootstrap = fixture_descriptor("sha256:b", 1024);
        let manifest = build_oci_manifest(&OciManifestInputs {
            subject_manifest_digest: "sha256:subject",
            config_digest: "sha256:cfg",
            config_size: 42,
            bootstrap: &bootstrap,
            zran_indexes: &[],
            prefetch_blob: None,
        });
        assert_eq!(manifest.media_type, OCI_MANIFEST_MEDIATYPE);
        assert_eq!(manifest.config.media_type, AUTO_ACCEL_CONFIG_MEDIATYPE);
        assert_eq!(
            manifest.layers[0].media_type,
            AUTO_ACCEL_BOOTSTRAP_MEDIATYPE
        );
        assert_eq!(manifest.schema_version, 2);
    }

    #[test]
    fn layers_carry_bootstrap_indexes_and_optional_prefetch_in_order() {
        let bootstrap = fixture_descriptor("sha256:boot", 1024);
        let indexes = vec![
            fixture_index("sha256:l0", "sha256:idx0", 11),
            fixture_index("sha256:l1", "sha256:idx1", 22),
        ];
        let prefetch = fixture_descriptor("sha256:pre", 99);
        let manifest = build_oci_manifest(&OciManifestInputs {
            subject_manifest_digest: "sha256:subject",
            config_digest: "sha256:cfg",
            config_size: 42,
            bootstrap: &bootstrap,
            zran_indexes: &indexes,
            prefetch_blob: Some(&prefetch),
        });
        assert_eq!(manifest.layers.len(), 1 + 2 + 1);
        assert_eq!(manifest.layers[0].digest, "sha256:boot");
        assert_eq!(manifest.layers[1].digest, "sha256:idx0");
        assert_eq!(manifest.layers[2].digest, "sha256:idx1");
        assert_eq!(manifest.layers[3].digest, "sha256:pre");
        assert_eq!(manifest.layers[3].media_type, AUTO_ACCEL_PREFETCH_MEDIATYPE);
    }

    #[test]
    fn index_layers_carry_layer_digest_annotation_pinning_original_gzip_layer() {
        let bootstrap = fixture_descriptor("sha256:boot", 1024);
        let indexes = vec![fixture_index(
            "sha256:original-gzip-layer",
            "sha256:zran-index",
            11,
        )];
        let manifest = build_oci_manifest(&OciManifestInputs {
            subject_manifest_digest: "sha256:subject",
            config_digest: "sha256:cfg",
            config_size: 42,
            bootstrap: &bootstrap,
            zran_indexes: &indexes,
            prefetch_blob: None,
        });
        let idx_layer = &manifest.layers[1];
        assert_eq!(
            idx_layer
                .annotations
                .get(AUTO_ACCEL_LAYER_DIGEST_ANNOTATION),
            Some(&"sha256:original-gzip-layer".to_string()),
            "consumer needs the layer-digest annotation to wire the zran index against the right blob_path"
        );
    }

    #[test]
    fn no_prefetch_means_no_prefetch_layer() {
        let bootstrap = fixture_descriptor("sha256:b", 1024);
        let manifest = build_oci_manifest(&OciManifestInputs {
            subject_manifest_digest: "sha256:subject",
            config_digest: "sha256:cfg",
            config_size: 42,
            bootstrap: &bootstrap,
            zran_indexes: &[],
            prefetch_blob: None,
        });
        assert!(
            !manifest
                .layers
                .iter()
                .any(|l| l.media_type == AUTO_ACCEL_PREFETCH_MEDIATYPE),
            "absent prefetch_blob must not synthesize a layer entry"
        );
    }

    #[test]
    fn subject_annotation_pins_gc_anchor() {
        let bootstrap = fixture_descriptor("sha256:b", 1024);
        let manifest = build_oci_manifest(&OciManifestInputs {
            subject_manifest_digest: "sha256:e6017bb",
            config_digest: "sha256:cfg",
            config_size: 42,
            bootstrap: &bootstrap,
            zran_indexes: &[],
            prefetch_blob: None,
        });
        assert_eq!(
            manifest.annotations.get(AUTO_ACCEL_SUBJECT_ANNOTATION),
            Some(&"sha256:e6017bb".to_string())
        );
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let bootstrap = fixture_descriptor("sha256:b", 1024);
        let manifest = build_oci_manifest(&OciManifestInputs {
            subject_manifest_digest: "sha256:subject",
            config_digest: "sha256:cfg",
            config_size: 42,
            bootstrap: &bootstrap,
            zran_indexes: &[fixture_index("sha256:l0", "sha256:idx0", 11)],
            prefetch_blob: None,
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let parsed: OciImageManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.media_type, OCI_MANIFEST_MEDIATYPE);
        assert_eq!(parsed.layers.len(), 2);
        // mediaType (camelCase) is the correct on-wire name per OCI spec.
        let raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            raw.get("mediaType").is_some(),
            "wire must use camelCase mediaType"
        );
        assert!(raw.get("layers").unwrap()[0].get("mediaType").is_some());
    }
}
