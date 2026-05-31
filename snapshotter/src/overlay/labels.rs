// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Label and snapshot-key helpers used by the overlay engine.

use crate::source::CRI_IMAGE_REF;
use std::collections::HashMap;

pub(super) fn normalize_parent(parent: &str) -> Option<&str> {
    if parent.is_empty() {
        None
    } else {
        Some(parent)
    }
}

pub(super) fn image_ref(labels: &HashMap<String, String>) -> Option<&str> {
    labels.get(CRI_IMAGE_REF).map(|value| value.as_str())
}

/// A stored snapshot row may carry an `image_ref` left over from an earlier
/// (buggy) snapshotter version that wrote a bare digest like
/// `sha256:abc…` instead of a real image reference. Reject those so the
/// daemon supervisor never tries to build a registry URL from a digest.
pub(super) fn is_image_ref_like(s: &str) -> bool {
    !s.is_empty() && !s.starts_with("sha256:") && !s.starts_with("sha512:")
}

/// Extract the bootstrap layer digest (`sha256:…`) from a snapshot key whose
/// format is `<namespace>/<id>/<digest>`, e.g. the bootstrap snapshot key
/// committed by containerd at image pull time.
pub(super) fn bootstrap_digest_from_key(key: &str) -> Option<&str> {
    let last = key.rsplit('/').next()?;
    if last.starts_with("sha256:") || last.starts_with("sha512:") {
        Some(last)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_ref_like_rejects_bare_digests() {
        assert!(!is_image_ref_like(""));
        assert!(!is_image_ref_like("sha256:abc"));
        assert!(!is_image_ref_like("sha512:def"));
        assert!(is_image_ref_like("registry.example.com/ns/app:tag"));
    }

    #[test]
    fn bootstrap_digest_from_key_uses_last_path_component() {
        assert_eq!(
            bootstrap_digest_from_key("k8s.io/123/sha256:deadbeef"),
            Some("sha256:deadbeef")
        );
        assert_eq!(bootstrap_digest_from_key("plain-key"), None);
    }

    #[test]
    fn empty_parent_normalizes_to_none() {
        assert_eq!(normalize_parent(""), None);
        assert_eq!(normalize_parent("parent"), Some("parent"));
    }
}
