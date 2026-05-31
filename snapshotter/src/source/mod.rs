// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Image source detection and handling.
//!
//! Supports referrer-based detection, OCI image encryption, and
//! direct RAFS bootstrap loading.

pub mod encryption;
pub mod labels;
pub mod referrer;

pub use labels::{
    classify_layer, target_snapshot_ref, LayerKind, CRI_IMAGE_REF, CRI_LAYER_DIGEST,
    NYDUS_BLOB_DIGEST, NYDUS_BLOB_SIZE, NYDUS_DATA_LAYER, NYDUS_META_LAYER, NYDUS_REF_LAYER,
    TARGET_SNAPSHOT_REF,
};
