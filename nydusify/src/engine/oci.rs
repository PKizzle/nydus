// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Shared OCI-registry helpers used by the convert/copy/check/mount engines:
//! registry-client option construction, manifest-vs-index detection, platform
//! selection out of an image index, and blob-id derivation.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use registry_client::{Descriptor, FetchedManifest, Index, RegistryClient, RegistryClientOptions};
use tracing::debug;

use crate::engine::retry::RetryPolicy;

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

/// Every index entry that is a convertible image, formatted as
/// `os/arch[/variant]` selectors. Used to expand `--all-platforms`.
///
/// Three kinds of entry are excluded, all of which would otherwise become
/// spurious conversion work:
///
/// * buildkit attaches SBOM/provenance attestations as extra index entries
///   tagged `unknown/unknown` (their layers are `application/vnd.in-toto+json`,
///   not tars). `docker.io/library/busybox` carries them, so `--all-platforms`
///   hits this on a very ordinary source.
/// * the nydus half of a dual-manifest index published by
///   `--attach-oci-manifest`: it carries the *same* platform as its OCI sibling,
///   so without this filter re-converting an already-attached tag yields the
///   platform twice — either a nonsensical "source resolves to 2 platforms
///   (linux/amd64, linux/amd64)" error, or (with `--merge-platform`) a doubled
///   conversion publishing two entries for one platform.
/// * exact duplicates after normalisation, so a hand-assembled index that names
///   one platform twice still converts it once.
pub fn all_platform_selectors(index: &Index) -> Vec<String> {
    let mut seen: Vec<(String, String, Option<String>)> = Vec::new();
    let mut selectors = Vec::new();
    for desc in &index.manifests {
        if registry_client::is_nydus_entry(desc) {
            continue;
        }
        let Some(p) = desc.platform.as_ref() else {
            continue;
        };
        if p.os.is_empty() || p.architecture.is_empty() {
            continue;
        }
        if p.os == "unknown" && p.architecture == "unknown" {
            continue;
        }
        let key = (
            p.os.clone(),
            p.architecture.clone(),
            p.normalized_variant().map(str::to_string),
        );
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        selectors.push(match &p.variant {
            Some(v) => format!("{}/{}/{}", p.os, p.architecture, v),
            None => format!("{}/{}", p.os, p.architecture),
        });
    }
    selectors
}

/// Select the manifest descriptor matching `platform_selector` from an index.
///
/// Matching is on NORMALISED platforms (see
/// [`registry_client::Platform::matches_selector`]): `linux/arm64` and
/// `linux/arm64/v8` are one platform, because containerd's `platforms.Normalize`
/// strips the `v8` while Docker Hub's manifest lists and UI spell it out — a
/// user copying `linux/arm64/v8` from Hub must not miss a buildx-published
/// `arm64` entry.
///
/// A selector naming no variant prefers an exact (normalised) match, but falls
/// back to any entry for that os/arch so `linux/arm` still resolves against an
/// index of `arm/v6` + `arm/v7`. That fallback is genuinely ambiguous — the
/// entries are different images — so it is logged.
pub fn select_platform<'a>(index: &'a Index, platform_selector: &str) -> Result<&'a Descriptor> {
    select_matching_platform(index, platform_selector, |_| true)
}

/// Select the NYDUS manifest matching `platform_selector`, falling back to the
/// plain platform match when the index marks no nydus entry.
///
/// `--attach-oci-manifest` publishes both halves of a conversion under one tag,
/// for the same platform, with the OCI half deliberately FIRST so that plain
/// consumers land on it. A reader that wants the nydus half therefore cannot take
/// the first platform match the way [`select_platform`] does — it has to key on
/// the nydus markers, exactly as the snapshotter does.
///
/// The fallback is what keeps an unmarked image working: a plain nydus manifest
/// list, which is what a conversion without `--attach-oci-manifest` publishes,
/// carries no marker on its entries and is still a nydus image.
pub fn select_nydus_platform<'a>(
    index: &'a Index,
    platform_selector: &str,
) -> Result<&'a Descriptor> {
    match select_matching_platform(index, platform_selector, registry_client::is_nydus_entry) {
        Ok(found) => Ok(found),
        Err(_) => select_platform(index, platform_selector),
    }
}

fn select_matching_platform<'a>(
    index: &'a Index,
    platform_selector: &str,
    keep: impl Fn(&Descriptor) -> bool,
) -> Result<&'a Descriptor> {
    let (os, arch, variant) = parse_platform(platform_selector)?;
    let exact = |d: &&Descriptor| {
        keep(d)
            && d.platform
                .as_ref()
                .is_some_and(|p| p.matches_selector(&os, &arch, variant.as_deref()))
    };
    if let Some(found) = index.manifests.iter().find(exact) {
        return Ok(found);
    }
    if variant.is_none() {
        let loose = |d: &&Descriptor| {
            keep(d)
                && d.platform
                    .as_ref()
                    .is_some_and(|p| p.os == os && p.architecture == arch)
        };
        let mut candidates = index.manifests.iter().filter(loose);
        if let Some(found) = candidates.next() {
            if candidates.next().is_some() {
                tracing::warn!(
                    platform = platform_selector,
                    chosen = ?found.platform.as_ref().and_then(|p| p.variant.as_deref()),
                    "the index carries several variants for this platform; picking the first — \
                     name the variant explicitly to choose"
                );
            }
            return Ok(found);
        }
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

/// Where a blob's bytes come from when it actually has to be uploaded.
pub enum BlobSource<'a> {
    /// Already on local disk (the converter downloaded it to build from).
    File(&'a Path),
    /// Download from the source registry into `staging` first, then upload.
    Download {
        client: &'a RegistryClient,
        staging: &'a Path,
    },
}

/// Make `digest` resolvable in `target_repo`, doing the least work that
/// achieves it: nothing when source and target are the same repo, nothing when
/// the target already has it, a cross-repo mount when both repos live on one
/// registry, and only failing that an upload.
///
/// This is the one place that cascade is written. It used to exist four times —
/// in `copy`, in `optimize`, and twice in the converter — with subtly different
/// semantics each time, so a fix to the mount fallback or the retry behaviour
/// had to be rediscovered for each copy.
pub async fn ensure_blob_in_repo(
    target_client: &RegistryClient,
    target_repo: &str,
    source_repo: Option<&str>,
    same_registry: bool,
    digest: &str,
    source: BlobSource<'_>,
    retry: &RetryPolicy,
) -> Result<()> {
    // Same repo on the same registry: the blob is literally already there, and
    // a HEAD would only confirm what the reference guarantees.
    if same_registry && source_repo == Some(target_repo) {
        return Ok(());
    }
    if target_client.head_blob(target_repo, digest).await? {
        debug!(%digest, "blob already present in target; skipping");
        return Ok(());
    }
    if same_registry
        && let Some(from) = source_repo
        && target_client
            .mount_blob(target_repo, digest, from)
            .await
            .unwrap_or(false)
    {
        debug!(%digest, %from, "cross-repo mounted blob");
        return Ok(());
    }
    match source {
        BlobSource::File(path) => {
            retry
                .run("push blob", || {
                    target_client.push_blob_file(target_repo, path)
                })
                .await
                .with_context(|| format!("push blob {digest}"))?;
        }
        BlobSource::Download { client, staging } => {
            let from = source_repo.context("downloading a blob needs a source repository")?;
            let tmp = staging.join(blob_hex(digest));
            client
                .get_blob_to_file(from, digest, &tmp)
                .await
                .with_context(|| format!("download blob {digest}"))?;
            retry
                .run("copy blob", || {
                    target_client.push_blob_file(target_repo, &tmp)
                })
                .await
                .with_context(|| format!("push blob {digest}"))?;
            let _ = std::fs::remove_file(&tmp);
        }
    }
    Ok(())
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
    fetch_selected_manifest(client, repo, reference, platform, select_platform).await
}

/// Fetch the nydus manifest for `platform` behind a reference that may be an
/// index. Readers of a converted image want this rather than
/// [`fetch_platform_manifest`], whose first-match rule lands on the OCI half of a
/// dual-manifest tag. See [`select_nydus_platform`].
pub async fn fetch_nydus_platform_manifest(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    platform: &str,
) -> Result<FetchedManifest> {
    fetch_selected_manifest(client, repo, reference, platform, select_nydus_platform).await
}

async fn fetch_selected_manifest(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    platform: &str,
    select: for<'a> fn(&'a Index, &str) -> Result<&'a Descriptor>,
) -> Result<FetchedManifest> {
    let fetched = client.get_manifest(repo, reference).await?;
    if !is_index(fetched.content_type.as_deref(), &fetched.bytes) {
        return Ok(fetched);
    }
    let index: Index = serde_json::from_slice(&fetched.bytes)
        .map_err(|e| anyhow!("parse image index for {repo}:{reference}: {e}"))?;
    let selected = select(&index, platform)?;
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

    /// containerd's `platforms.Normalize` strips arm64's `v8` (so buildx-pushed
    /// indexes carry a bare `arm64`), while Docker Hub shows `linux/arm64/v8`.
    /// A user copying either spelling must resolve against either index.
    #[test]
    fn select_platform_normalizes_the_arm64_v8_spelling() {
        let bare = index_of(vec![platform_desc("linux", "arm64", None, "sha256:arm")]);
        let spelled = index_of(vec![platform_desc(
            "linux",
            "arm64",
            Some("v8"),
            "sha256:arm",
        )]);
        for index in [&bare, &spelled] {
            for selector in ["linux/arm64", "linux/arm64/v8"] {
                assert_eq!(
                    select_platform(index, selector).unwrap().digest,
                    "sha256:arm",
                    "{selector} must resolve regardless of how the index spells v8"
                );
            }
        }
    }

    /// 32-bit arm variants are different images, so an explicit variant must be
    /// honoured exactly; a bare `linux/arm` falls back to the first entry.
    #[test]
    fn select_platform_honours_explicit_arm_variants() {
        let index = index_of(vec![
            platform_desc("linux", "arm", Some("v7"), "sha256:v7"),
            platform_desc("linux", "arm", Some("v6"), "sha256:v6"),
        ]);
        assert_eq!(
            select_platform(&index, "linux/arm/v6").unwrap().digest,
            "sha256:v6"
        );
        assert_eq!(
            select_platform(&index, "linux/arm/v7").unwrap().digest,
            "sha256:v7"
        );
        // Ambiguous, but resolvable: first entry wins (and is warned about).
        assert_eq!(
            select_platform(&index, "linux/arm").unwrap().digest,
            "sha256:v7"
        );
        // A variant the index does not carry is a miss, not a loose match.
        assert!(select_platform(&index, "linux/arm/v5").is_err());
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

    fn nydus_desc(os: &str, arch: &str, digest: &str) -> Descriptor {
        let mut d = platform_desc(os, arch, None, digest);
        d.artifact_type = Some(registry_client::NYDUS_MANIFEST_ARTIFACT_TYPE.to_string());
        d
    }

    #[test]
    fn select_nydus_platform_prefers_the_nydus_half_of_a_dual_manifest_index() {
        // --attach-oci-manifest orders the OCI half first, for the same platform,
        // so a first-match selection lands on the wrong one.
        let index = index_of(vec![
            platform_desc("linux", "amd64", None, "sha256:oci-amd"),
            platform_desc("linux", "arm64", None, "sha256:oci-arm"),
            nydus_desc("linux", "arm64", "sha256:nydus-arm"),
        ]);
        assert_eq!(
            select_platform(&index, "linux/arm64").unwrap().digest,
            "sha256:oci-arm"
        );
        assert_eq!(
            select_nydus_platform(&index, "linux/arm64").unwrap().digest,
            "sha256:nydus-arm"
        );
        // A platform with no nydus entry still resolves to its OCI manifest.
        assert_eq!(
            select_nydus_platform(&index, "linux/amd64").unwrap().digest,
            "sha256:oci-amd"
        );
    }

    #[test]
    fn select_nydus_platform_falls_back_to_an_unmarked_index() {
        // A conversion published without --attach-oci-manifest is a nydus image
        // whose entries carry no marker at all.
        let index = index_of(vec![
            platform_desc("linux", "amd64", None, "sha256:amd"),
            platform_desc("linux", "arm64", None, "sha256:arm"),
        ]);
        assert_eq!(
            select_nydus_platform(&index, "linux/arm64").unwrap().digest,
            "sha256:arm"
        );
        assert!(select_nydus_platform(&index, "linux/ppc64le").is_err());
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

    #[test]
    fn all_platform_selectors_skips_buildkit_attestations() {
        // buildkit tags SBOM/provenance attestations `unknown/unknown` rather than
        // omitting the platform, so the "has a platform" filter alone lets them
        // through and the converter then chokes on their in-toto layers.
        let index = index_of(vec![
            platform_desc("linux", "amd64", None, "sha256:amd"),
            platform_desc("unknown", "unknown", None, "sha256:sbom"),
            platform_desc("linux", "arm64", Some("v8"), "sha256:arm"),
            platform_desc("unknown", "unknown", None, "sha256:provenance"),
        ]);
        assert_eq!(
            all_platform_selectors(&index),
            vec!["linux/amd64".to_string(), "linux/arm64/v8".to_string()]
        );
    }

    /// A tag published by `--attach-oci-manifest` holds the OCI manifest and
    /// its nydus sibling under the SAME platform. Expanding `--all-platforms`
    /// over it must yield that platform once, or the converter either refuses
    /// ("resolves to 2 platforms (linux/amd64, linux/amd64)") or converts twice.
    #[test]
    fn all_platform_selectors_skips_the_nydus_half_of_a_dual_index() {
        let mut nydus = platform_desc("linux", "amd64", None, "sha256:nydus");
        nydus.artifact_type = Some(registry_client::NYDUS_MANIFEST_ARTIFACT_TYPE.to_string());
        if let Some(p) = nydus.platform.as_mut() {
            p.os_features = Some(vec![registry_client::NYDUS_OS_FEATURE.to_string()]);
        }
        let index = index_of(vec![
            platform_desc("linux", "amd64", None, "sha256:oci"),
            nydus,
        ]);
        assert_eq!(
            all_platform_selectors(&index),
            vec!["linux/amd64".to_string()]
        );
    }

    /// Even without nydus markers, one platform named twice converts once.
    #[test]
    fn all_platform_selectors_dedupes_normalized_duplicates() {
        let index = index_of(vec![
            platform_desc("linux", "arm64", Some("v8"), "sha256:a"),
            platform_desc("linux", "arm64", None, "sha256:b"),
        ]);
        assert_eq!(
            all_platform_selectors(&index),
            vec!["linux/arm64/v8".to_string()]
        );
    }
}
