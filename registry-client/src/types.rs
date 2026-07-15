// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! OCI image-spec serde types (descriptors, manifests, indexes), media-type
//! constants, and digest helpers.
//!
//! Hand-rolled serde types by workspace convention (no `oci-spec` crate).
//! Serialization skips absent optional fields so round-tripped manifests stay
//! byte-compatible with what registries and other OCI tooling produce, and
//! annotation maps are `BTreeMap`s so serialization is deterministic.

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// OCI image manifest media type.
pub const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// OCI image index media type.
pub const MEDIA_TYPE_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// OCI image config media type.
pub const MEDIA_TYPE_OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
/// OCI tar layer media type.
pub const MEDIA_TYPE_OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
/// OCI gzip-compressed tar layer media type.
pub const MEDIA_TYPE_OCI_LAYER_TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
/// Docker schema-2 manifest media type.
pub const MEDIA_TYPE_DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// Docker schema-2 manifest list media type.
pub const MEDIA_TYPE_DOCKER_MANIFEST_LIST: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
/// Docker container config media type.
pub const MEDIA_TYPE_DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
/// Docker gzip-compressed tar layer media type.
pub const MEDIA_TYPE_DOCKER_LAYER_TAR_GZIP: &str =
    "application/vnd.docker.image.rootfs.diff.tar.gzip";
/// Raw blob media type (used as the Accept header for blob GETs).
pub const MEDIA_TYPE_OCTET_STREAM: &str = "application/octet-stream";

/// Nydus RAFS data-blob layer media type. For zran/targz-ref images a data
/// blob's id equals the original OCI gzip layer digest.
pub const MEDIA_TYPE_NYDUS_BLOB: &str = "application/vnd.oci.image.layer.nydus.blob.v1";
/// Nydus bootstrap media type as used by nydus referrer artifacts
/// (exercised by `misc/fanotify/b4b-referrer-serving-test.sh`).
pub const MEDIA_TYPE_NYDUS_BOOTSTRAP: &str = "application/vnd.oci.image.bootstrap.nydus.v1";
/// Nydus bootstrap *layer* media type as published by the Go nydusify
/// (`...layer.nydus.bootstrap.v1`); kept alongside [`MEDIA_TYPE_NYDUS_BOOTSTRAP`]
/// because both shapes exist in the wild.
pub const MEDIA_TYPE_NYDUS_BOOTSTRAP_LAYER: &str =
    "application/vnd.oci.image.layer.nydus.bootstrap.v1";

/// Annotation marking a nydus bootstrap layer
/// (`containerd.io/snapshot/nydus-bootstrap = "true"`).
pub const ANNOTATION_NYDUS_BOOTSTRAP: &str = "containerd.io/snapshot/nydus-bootstrap";

/// Accept header for manifest GET/HEAD requests: all four manifest/index
/// media types this client understands.
pub const MANIFEST_ACCEPT: &str = concat!(
    "application/vnd.oci.image.manifest.v1+json, ",
    "application/vnd.docker.distribution.manifest.v2+json, ",
    "application/vnd.oci.image.index.v1+json, ",
    "application/vnd.docker.distribution.manifest.list.v2+json"
);

/// An OCI content descriptor: a typed, sized, digest-addressed reference to a
/// blob or manifest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    /// Media type of the referenced content.
    pub media_type: String,
    /// Content digest (`sha256:<hex>`).
    pub digest: String,
    /// Size of the referenced content in bytes.
    #[serde(default)]
    pub size: u64,
    /// Artifact type (only meaningful on manifest descriptors inside a
    /// referrers index).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    /// Optional alternate fetch URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    /// Arbitrary key/value annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Target platform (index entries only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

impl Descriptor {
    /// Build a descriptor for in-memory content: computes the sha256 digest
    /// and size of `bytes`.
    pub fn for_bytes(media_type: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            media_type: media_type.into(),
            digest: sha256_digest(bytes),
            size: bytes.len() as u64,
            ..Self::default()
        }
    }
}

/// Platform selector on index descriptors.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    /// CPU architecture (GOARCH-style, e.g. `amd64`, `arm64`).
    pub architecture: String,
    /// Operating system (GOOS-style, e.g. `linux`).
    pub os: String,
    /// OS version (Windows images).
    #[serde(
        default,
        rename = "os.version",
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,
    /// Architecture variant (e.g. `v8` for arm64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

/// An OCI image manifest (also parses docker schema-2 manifests).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// Manifest schema version; always `2` for OCI/docker-v2 manifests.
    pub schema_version: u32,
    /// Manifest media type ([`MEDIA_TYPE_OCI_MANIFEST`] or
    /// [`MEDIA_TYPE_DOCKER_MANIFEST`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Artifact type for OCI 1.1 artifact manifests (e.g. a nydus referrer
    /// artifact carrying a bootstrap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    /// Image (or artifact) config descriptor.
    pub config: Descriptor,
    /// Layer descriptors in order.
    #[serde(default)]
    pub layers: Vec<Descriptor>,
    /// Subject descriptor: the manifest this artifact refers to (drives the
    /// OCI 1.1 referrers API; required when pushing referrer artifacts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Descriptor>,
    /// Arbitrary key/value annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// An OCI image index (also parses docker manifest lists and OCI referrers
/// API responses, which are indexes too).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Index {
    /// Index schema version; always `2`.
    pub schema_version: u32,
    /// Index media type ([`MEDIA_TYPE_OCI_INDEX`] or
    /// [`MEDIA_TYPE_DOCKER_MANIFEST_LIST`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Manifest descriptors (per-platform images, or referrer artifacts in a
    /// referrers API response).
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
    /// Arbitrary key/value annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// An OCI image config (the blob referenced by a manifest's `config`
/// descriptor).
///
/// Only the two fields nydusify rewrites during conversion — [`rootfs`](Self::
/// rootfs) (its `diff_ids`) and [`history`](Self::history) — are typed. Every
/// other field (`architecture`, `os`, `config`, `created`, `variant`, …) is
/// preserved verbatim through [`extra`](Self::extra) so re-serializing the
/// rewritten config keeps the rest of the image config byte-for-byte
/// equivalent in content.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageConfig {
    /// The layer filesystem, whose `diff_ids` must have exactly one entry per
    /// manifest layer (containerd's unpacker rejects a mismatch).
    #[serde(default)]
    pub rootfs: RootFs,
    /// Build history; the nydus converter appends one bootstrap-layer entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<History>,
    /// All other image-config fields, preserved as-is.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// The `rootfs` section of an OCI image config.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootFs {
    /// Always `"layers"` for the layer rootfs type.
    #[serde(rename = "type")]
    pub type_: String,
    /// The per-layer diff ids (uncompressed-layer digests), one per manifest
    /// layer, in order.
    #[serde(default)]
    pub diff_ids: Vec<String>,
}

/// One entry in an OCI image config's `history` array.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct History {
    /// Creation timestamp (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// The command that created the layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Author of the build step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Free-form comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Whether this history entry corresponds to an empty (non-filesystem)
    /// layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_layer: Option<bool>,
}

/// Compute the OCI digest string (`sha256:<hex>`) of `bytes`.
pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Verify that `bytes` hash to `expected` (a `sha256:<hex>` digest string).
/// Only sha256 is supported; other algorithms are rejected.
pub fn verify_digest(bytes: &[u8], expected: &str) -> Result<()> {
    let want = expected
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("unsupported digest {expected}; only sha256 is supported"))?;
    let got = hex::encode(Sha256::digest(bytes));
    if !got.eq_ignore_ascii_case(want) {
        bail!("digest mismatch: expected {expected}, computed sha256:{got}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The referrer artifact manifest shape pushed by
    /// `misc/fanotify/b4b-referrer-serving-test.sh` (data blob listed BEFORE
    /// the annotated bootstrap layer), extended with the `subject` field used
    /// when publishing via the OCI 1.1 referrers API.
    const B4B_ARTIFACT_JSON: &str = r#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.oci.image.layer.nydus.blob.v1",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "size": 2
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.nydus.blob.v1",
                "digest": "sha256:8c2e9ec48c2ee5c2e9ec48c2ee5c2e9ec48c2ee5c2e9ec48c2ee5c2e9ec48c2e",
                "size": 196608
            },
            {
                "mediaType": "application/vnd.oci.image.bootstrap.nydus.v1",
                "digest": "sha256:1b6453892473a467d07372d45eb05abc2031647a1b6453892473a467d07372d4",
                "size": 24576,
                "annotations": {"containerd.io/snapshot/nydus-bootstrap": "true"}
            }
        ],
        "subject": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a94a8fe5ccb19ba61c4c0873",
            "size": 1024
        }
    }"#;

    #[test]
    fn b4b_artifact_fixture_round_trips() {
        let manifest: Manifest = serde_json::from_str(B4B_ARTIFACT_JSON).unwrap();
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(
            manifest.media_type.as_deref(),
            Some(MEDIA_TYPE_OCI_MANIFEST)
        );
        assert_eq!(
            manifest.artifact_type.as_deref(),
            Some(MEDIA_TYPE_NYDUS_BLOB)
        );
        assert_eq!(manifest.config.media_type, MEDIA_TYPE_OCI_CONFIG);
        assert_eq!(manifest.config.size, 2);

        // Layer ordering stresses bootstrap selection: data blob first, bootstrap second.
        assert_eq!(manifest.layers.len(), 2);
        assert_eq!(manifest.layers[0].media_type, MEDIA_TYPE_NYDUS_BLOB);
        let bootstrap = &manifest.layers[1];
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

        let subject = manifest.subject.as_ref().unwrap();
        assert_eq!(subject.media_type, MEDIA_TYPE_OCI_MANIFEST);
        assert_eq!(subject.size, 1024);

        // Round trip: serialize -> reparse -> structurally equal.
        let reserialized = serde_json::to_string(&manifest).unwrap();
        let reparsed: Manifest = serde_json::from_str(&reserialized).unwrap();
        assert_eq!(reparsed, manifest);
        // Field names stay camelCase on the wire.
        assert!(reserialized.contains("\"schemaVersion\":2"));
        assert!(reserialized.contains("\"mediaType\""));
        assert!(reserialized.contains("\"artifactType\""));
        assert!(reserialized.contains("\"subject\""));
    }

    #[test]
    fn absent_optional_fields_are_not_serialized() {
        let manifest = Manifest {
            schema_version: 2,
            media_type: Some(MEDIA_TYPE_OCI_MANIFEST.to_string()),
            config: Descriptor::for_bytes(MEDIA_TYPE_OCI_CONFIG, b"{}"),
            ..Manifest::default()
        };
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(!json.contains("subject"));
        assert!(!json.contains("annotations"));
        assert!(!json.contains("artifactType"));
        assert!(!json.contains("platform"));
        assert!(!json.contains("urls"));
    }

    #[test]
    fn index_with_platforms_round_trips() {
        let json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:aaa",
                    "size": 7143,
                    "platform": {"architecture": "amd64", "os": "linux"}
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:bbb",
                    "size": 7682,
                    "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}
                }
            ]
        }"#;
        let index: Index = serde_json::from_str(json).unwrap();
        assert_eq!(index.manifests.len(), 2);
        let arm = &index.manifests[1];
        let platform = arm.platform.as_ref().unwrap();
        assert_eq!(platform.architecture, "arm64");
        assert_eq!(platform.variant.as_deref(), Some("v8"));

        let reparsed: Index =
            serde_json::from_str(&serde_json::to_string(&index).unwrap()).unwrap();
        assert_eq!(reparsed, index);
    }

    #[test]
    fn descriptor_for_bytes_computes_digest_and_size() {
        let desc = Descriptor::for_bytes(MEDIA_TYPE_OCTET_STREAM, b"{}");
        assert_eq!(desc.size, 2);
        // sha256("{}") — the digest of the empty JSON config.
        assert_eq!(
            desc.digest,
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn digest_helper_and_verification() {
        let bytes = b"registry-client digest test";
        let digest = sha256_digest(bytes);
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
        verify_digest(bytes, &digest).expect("matching digest must verify");
        // Case-insensitive hex comparison.
        verify_digest(bytes, &digest.to_uppercase().replace("SHA256", "sha256"))
            .expect("uppercase hex must verify");
        verify_digest(b"tampered", &digest).expect_err("mismatch must be rejected");
        verify_digest(bytes, "sha512:deadbeef").expect_err("non-sha256 must be rejected");
    }
}
