// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Referrer-artifact push seam (Phase 4c).
//!
//! Transparent node-local acceleration never pushes a referrer, but the
//! registry-publish flow (`nydusify convert --with-referrer`) is expected to
//! attach the pushed nydus manifest to the *source* image as an OCI 1.1
//! referrer artifact (`subject` = the source manifest descriptor captured at
//! pull time). That end (blob/artifact layout, referrers-API digest push plus
//! the `sha256-<digest>` fallback tag) is intentionally *not* implemented here;
//! it is scoped to a separate task.
//!
//! This module exposes the seam so the convert pipeline can call it
//! unconditionally: it is a no-op when `--with-referrer` was not requested, and
//! a loud, honest error when it was — so the feature never silently appears to
//! work.

use anyhow::{Result, bail};
use registry_client::Descriptor;

/// Referrer-push seam. Called after the nydus manifest has been pushed.
///
/// * `with_referrer` — the `--with-referrer` flag.
/// * `pushed` — descriptor of the nydus manifest just pushed to the target.
/// * `source_manifest` — descriptor of the source image manifest captured at
///   pull time; becomes the referrer artifact's `subject` once wired.
///
/// Returns `Ok(())` when `with_referrer` is unset. When set, it bails with a
/// clear "not yet wired (P4c)" message rather than pretending to publish.
pub fn maybe_push_referrer(
    with_referrer: bool,
    pushed: &Descriptor,
    source_manifest: &Descriptor,
) -> Result<()> {
    if !with_referrer {
        return Ok(());
    }
    bail!(
        "--with-referrer referrer-artifact push is not yet wired (P4c): the nydus manifest \
         {} was pushed, but no referrer artifact was attached to source subject {}",
        pushed.digest,
        source_manifest.digest
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_client::types::{MEDIA_TYPE_NYDUS_BLOB, MEDIA_TYPE_OCI_MANIFEST};

    fn desc(media: &str, digest: &str) -> Descriptor {
        Descriptor {
            media_type: media.to_string(),
            digest: digest.to_string(),
            size: 1,
            ..Descriptor::default()
        }
    }

    #[test]
    fn no_op_when_flag_unset() {
        let pushed = desc(MEDIA_TYPE_NYDUS_BLOB, "sha256:aaa");
        let source = desc(MEDIA_TYPE_OCI_MANIFEST, "sha256:bbb");
        assert!(maybe_push_referrer(false, &pushed, &source).is_ok());
    }

    #[test]
    fn bails_honestly_when_flag_set() {
        let pushed = desc(MEDIA_TYPE_NYDUS_BLOB, "sha256:aaa");
        let source = desc(MEDIA_TYPE_OCI_MANIFEST, "sha256:bbb");
        let err = maybe_push_referrer(true, &pushed, &source).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("P4c"));
        assert!(msg.contains("sha256:bbb"));
    }
}
