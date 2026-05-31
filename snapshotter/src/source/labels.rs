// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Containerd / nydus snapshot label constants and classification helpers.
//!
//! Mirrors the authoritative set from the Go nydus-snapshotter
//! (`pkg/label/label.go` and `pkg/converter/constant.go`) so the Rust
//! snapshotter can speak the same protocol that containerd's image
//! unpacker uses to hand off Nydus blob layers without invoking a stream
//! processor.

use std::collections::HashMap;

/// Set by containerd's image unpacker on `Prepare` to indicate the target
/// committed snapshot name (chain ID) for a layer extraction.
pub const TARGET_SNAPSHOT_REF: &str = "containerd.io/snapshot.ref";

/// Marks a layer as a Nydus data blob
/// (`application/vnd.oci.image.layer.nydus.blob.v1`).
pub const NYDUS_DATA_LAYER: &str = "containerd.io/snapshot/nydus-blob";

/// Marks a layer as a Nydus bootstrap (metadata) layer.
pub const NYDUS_META_LAYER: &str = "containerd.io/snapshot/nydus-bootstrap";

/// Marks a layer as a Nydus referenced (foreign) blob.
pub const NYDUS_REF_LAYER: &str = "containerd.io/snapshot/nydus-ref";

/// Digest of the underlying Nydus blob, set by image builders.
pub const NYDUS_BLOB_DIGEST: &str = "containerd.io/snapshot/nydus-blob-digest";

/// Size of the underlying Nydus blob, set by image builders.
pub const NYDUS_BLOB_SIZE: &str = "containerd.io/snapshot/nydus-blob-size";

/// CRI annotation: digest of the layer this snapshot represents.
pub const CRI_LAYER_DIGEST: &str = "containerd.io/snapshot/cri.layer-digest";

/// CRI annotation: full image reference (`docker.io/library/nginx:latest`) of the
/// image whose chain this snapshot belongs to.
pub const CRI_IMAGE_REF: &str = "containerd.io/snapshot/cri.image-ref";

/// Classification of a snapshot's underlying layer based on its labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerKind {
    /// A Nydus blob (data) layer carrying the
    /// `application/vnd.oci.image.layer.nydus.blob.v1` media type.
    NydusData,
    /// A Nydus bootstrap (metadata) layer, packaged as a standard tar+gzip.
    NydusMeta,
    /// A foreign / referenced Nydus blob.
    NydusRef,
    /// A regular OCI layer (no Nydus annotations present).
    Other,
}

/// Classify a layer using only its labels. Used at `Prepare` time to decide
/// whether to short-circuit containerd's unpacker.
pub fn classify_layer(labels: &HashMap<String, String>) -> LayerKind {
    if labels.contains_key(NYDUS_DATA_LAYER) {
        LayerKind::NydusData
    } else if labels.contains_key(NYDUS_META_LAYER) {
        LayerKind::NydusMeta
    } else if labels.contains_key(NYDUS_REF_LAYER) {
        LayerKind::NydusRef
    } else {
        LayerKind::Other
    }
}

/// Return the target committed snapshot key the unpacker is preparing, if any.
pub fn target_snapshot_ref(labels: &HashMap<String, String>) -> Option<&str> {
    labels.get(TARGET_SNAPSHOT_REF).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn classify_nydus_data_layer() {
        let l = labels(&[(NYDUS_DATA_LAYER, "true")]);
        assert_eq!(classify_layer(&l), LayerKind::NydusData);
    }

    #[test]
    fn classify_nydus_meta_layer() {
        let l = labels(&[(NYDUS_META_LAYER, "true")]);
        assert_eq!(classify_layer(&l), LayerKind::NydusMeta);
    }

    #[test]
    fn classify_nydus_ref_layer() {
        let l = labels(&[(NYDUS_REF_LAYER, "sha256:abc")]);
        assert_eq!(classify_layer(&l), LayerKind::NydusRef);
    }

    #[test]
    fn classify_plain_oci_layer() {
        let l = labels(&[(TARGET_SNAPSHOT_REF, "sha256:abc")]);
        assert_eq!(classify_layer(&l), LayerKind::Other);
    }

    #[test]
    fn data_takes_precedence_over_meta_when_both_present() {
        let l = labels(&[(NYDUS_DATA_LAYER, "true"), (NYDUS_META_LAYER, "true")]);
        assert_eq!(classify_layer(&l), LayerKind::NydusData);
    }

    #[test]
    fn target_ref_returns_label_value() {
        let l = labels(&[(TARGET_SNAPSHOT_REF, "sha256:deadbeef")]);
        assert_eq!(target_snapshot_ref(&l), Some("sha256:deadbeef"));
    }

    #[test]
    fn target_ref_absent_returns_none() {
        let l = labels(&[(NYDUS_DATA_LAYER, "true")]);
        assert_eq!(target_snapshot_ref(&l), None);
    }
}
