// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Shared OCI-registry helpers used by the convert/copy/check/mount engines:
//! registry-client option construction, manifest-vs-index detection, platform
//! selection out of an image index, and blob-id derivation.

use std::path::Path;

use anyhow::{Result, anyhow, bail};
use registry_client::{Descriptor, FetchedManifest, Index, RegistryClient, RegistryClientOptions};

/// Build [`RegistryClientOptions`] from the CLI's `--*-insecure` /
/// `--plain-http` / `--ca-cert` switches, keeping the secure, time-bounded
/// defaults for everything else.
pub fn client_options(
    insecure: bool,
    plain_http: bool,
    ca_cert_files: &[impl AsRef<Path>],
) -> RegistryClientOptions {
    RegistryClientOptions {
        plain_http,
        insecure_tls: insecure,
        ca_cert_files: ca_cert_files
            .iter()
            .map(|p| p.as_ref().to_path_buf())
            .collect(),
        ..RegistryClientOptions::default()
    }
}

/// Bare lowercase hex of an OCI digest (strips an `algo:` prefix). This is how
/// nydus names data blobs and keys the localfs/registry backend.
pub fn blob_hex(digest: &str) -> &str {
    match digest.split_once(':') {
        Some((_algo, hex)) => hex,
        None => digest,
    }
}

/// Whether a fetched manifest is an image index / manifest list. Uses the
/// declared content type when present, else a structural fallback.
pub fn is_index(content_type: Option<&str>, bytes: &[u8]) -> bool {
    if let Some(ct) = content_type {
        if ct.contains("index") || ct.contains("manifest.list") {
            return true;
        }
        if ct.contains("manifest.v") {
            return false;
        }
    }
    // Structural fallback: an index has a non-empty `manifests` array and no
    // `config` (which every image manifest has).
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(v) => v.get("config").is_none() && v.get("manifests").is_some_and(|m| m.is_array()),
        Err(_) => false,
    }
}

/// Parse a `os/arch[/variant]` platform selector.
pub fn parse_platform(selector: &str) -> Result<(String, String, Option<String>)> {
    let mut parts = selector.split('/');
    let os = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("empty platform selector"))?;
    let arch = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
        anyhow!("platform {selector:?} is missing an architecture (want os/arch)")
    })?;
    let variant = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
    Ok((os.to_string(), arch.to_string(), variant))
}

/// Split a comma-separated `--platform` value into individual `os/arch[/variant]`
/// selectors, dropping empty entries. A single selector yields a one-element
/// vec, so callers can treat single- and multi-platform requests uniformly.
pub fn parse_platform_list(value: &str) -> Result<Vec<String>> {
    let selectors: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if selectors.is_empty() {
        bail!("empty --platform value");
    }
    // Validate each up front so a typo fails before any network work.
    for sel in &selectors {
        parse_platform(sel)?;
    }
    Ok(selectors)
}

/// Every index entry that carries a platform field, formatted as
/// `os/arch[/variant]` selectors. Used to expand `--all-platforms`.
pub fn all_platform_selectors(index: &Index) -> Vec<String> {
    index
        .manifests
        .iter()
        .filter_map(|d| d.platform.as_ref())
        .filter(|p| !p.os.is_empty() && !p.architecture.is_empty())
        .map(|p| match &p.variant {
            Some(v) => format!("{}/{}/{}", p.os, p.architecture, v),
            None => format!("{}/{}", p.os, p.architecture),
        })
        .collect()
}

/// Select the manifest descriptor matching `platform_selector` from an index.
pub fn select_platform<'a>(index: &'a Index, platform_selector: &str) -> Result<&'a Descriptor> {
    let (os, arch, variant) = parse_platform(platform_selector)?;
    let matches = |d: &&Descriptor| {
        d.platform.as_ref().is_some_and(|p| {
            p.os == os
                && p.architecture == arch
                && variant
                    .as_ref()
                    .is_none_or(|v| p.variant.as_deref() == Some(v.as_str()))
        })
    };
    if let Some(found) = index.manifests.iter().find(matches) {
        return Ok(found);
    }
    let available: Vec<String> = index
        .manifests
        .iter()
        .filter_map(|d| d.platform.as_ref())
        .map(|p| match &p.variant {
            Some(v) => format!("{}/{}/{}", p.os, p.architecture, v),
            None => format!("{}/{}", p.os, p.architecture),
        })
        .collect();
    bail!(
        "no manifest in the index matches platform {platform_selector:?}; available: [{}]",
        available.join(", ")
    )
}

/// Fetch a manifest by `reference`, resolving an image index down to the single
/// manifest for `platform`. The returned [`FetchedManifest`] is the concrete
/// image manifest (never an index): its bytes/digest/content-type can be
/// re-pushed or parsed directly.
pub async fn fetch_platform_manifest(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    platform: &str,
) -> Result<FetchedManifest> {
    let fetched = client.get_manifest(repo, reference).await?;
    if !is_index(fetched.content_type.as_deref(), &fetched.bytes) {
        return Ok(fetched);
    }
    let index: Index = serde_json::from_slice(&fetched.bytes)
        .map_err(|e| anyhow!("parse image index for {repo}:{reference}: {e}"))?;
    let selected = select_platform(&index, platform)?;
    Ok(client.get_manifest(repo, &selected.digest).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_client::Platform;
    use registry_client::types::{MEDIA_TYPE_OCI_INDEX, MEDIA_TYPE_OCI_MANIFEST};

    #[test]
    fn blob_hex_strips_algorithm() {
        assert_eq!(blob_hex("sha256:deadbeef"), "deadbeef");
        assert_eq!(blob_hex("cafef00d"), "cafef00d");
    }

    #[test]
    fn index_detection_by_content_type_and_structure() {
        assert!(is_index(Some(MEDIA_TYPE_OCI_INDEX), b"{}"));
        assert!(is_index(
            Some("application/vnd.docker.distribution.manifest.list.v2+json"),
            b"{}"
        ));
        assert!(!is_index(Some(MEDIA_TYPE_OCI_MANIFEST), b"{}"));
        // Structural fallback (no content type): manifests[] and no config.
        assert!(is_index(None, br#"{"manifests":[{"digest":"sha256:a"}]}"#));
        assert!(!is_index(
            None,
            br#"{"config":{"digest":"sha256:c"},"layers":[]}"#
        ));
    }

    fn platform_desc(os: &str, arch: &str, variant: Option<&str>, digest: &str) -> Descriptor {
        Descriptor {
            media_type: MEDIA_TYPE_OCI_MANIFEST.to_string(),
            digest: digest.to_string(),
            platform: Some(Platform {
                architecture: arch.to_string(),
                os: os.to_string(),
                variant: variant.map(str::to_string),
                ..Platform::default()
            }),
            ..Descriptor::default()
        }
    }

    fn index_of(descs: Vec<Descriptor>) -> Index {
        Index {
            schema_version: 2,
            media_type: Some(MEDIA_TYPE_OCI_INDEX.to_string()),
            manifests: descs,
            annotations: None,
        }
    }

    #[test]
    fn select_platform_matches_os_arch_and_variant() {
        let index = index_of(vec![
            platform_desc("linux", "amd64", None, "sha256:amd"),
            platform_desc("linux", "arm64", Some("v8"), "sha256:arm"),
        ]);
        assert_eq!(
            select_platform(&index, "linux/amd64").unwrap().digest,
            "sha256:amd"
        );
        assert_eq!(
            select_platform(&index, "linux/arm64").unwrap().digest,
            "sha256:arm"
        );
        assert_eq!(
            select_platform(&index, "linux/arm64/v8").unwrap().digest,
            "sha256:arm"
        );
    }

    #[test]
    fn select_platform_reports_available_on_miss() {
        let index = index_of(vec![platform_desc("linux", "amd64", None, "sha256:amd")]);
        let err = select_platform(&index, "linux/ppc64le").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("linux/ppc64le"));
        assert!(msg.contains("linux/amd64"));
    }

    #[test]
    fn parse_platform_requires_arch() {
        assert!(parse_platform("linux").is_err());
        let (os, arch, variant) = parse_platform("linux/arm/v7").unwrap();
        assert_eq!((os.as_str(), arch.as_str()), ("linux", "arm"));
        assert_eq!(variant.as_deref(), Some("v7"));
    }

    #[test]
    fn parse_platform_list_splits_and_validates() {
        assert_eq!(
            parse_platform_list("linux/amd64, linux/arm64/v8 ,").unwrap(),
            vec!["linux/amd64".to_string(), "linux/arm64/v8".to_string()]
        );
        assert_eq!(
            parse_platform_list("linux/amd64").unwrap(),
            vec!["linux/amd64".to_string()]
        );
        // A malformed member fails the whole list up front.
        assert!(parse_platform_list("linux/amd64,linux").is_err());
        assert!(parse_platform_list("  ,  ").is_err());
    }

    #[test]
    fn all_platform_selectors_lists_platform_tagged_entries_only() {
        let index = index_of(vec![
            platform_desc("linux", "amd64", None, "sha256:amd"),
            platform_desc("linux", "arm64", Some("v8"), "sha256:arm"),
            // A bare descriptor (e.g. an attestation manifest) with no platform
            // is skipped.
            Descriptor {
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                digest: "sha256:att".to_string(),
                ..Descriptor::default()
            },
        ]);
        assert_eq!(
            all_platform_selectors(&index),
            vec!["linux/amd64".to_string(), "linux/arm64/v8".to_string()]
        );
    }
}
