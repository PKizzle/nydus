// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Minimal OCI image reference parser.
//!
//! Splits a reference like `docker.io/library/nginx:latest@sha256:abc…` into
//! `(host, repo, tag, digest)` and applies the well-known `docker.io` →
//! `registry-1.docker.io` rewrite that nydusd's registry backend expects.

/// Parsed components of an OCI image reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRef {
    /// Registry host as embedded in the reference (e.g. `docker.io`).
    pub host: String,
    /// Registry host used for HTTP requests (e.g. `registry-1.docker.io`).
    pub api_host: String,
    /// Repository path (e.g. `library/nginx`).
    pub repo: String,
    /// Tag, if present.
    pub tag: Option<String>,
    /// Digest, if present.
    pub digest: Option<String>,
}

/// Parse an image reference into its components.
///
/// Accepts inputs missing the registry host (defaults to `docker.io`) and
/// missing the repository namespace under `docker.io` (defaults to `library/`).
pub fn parse_image_ref(reference: &str) -> Option<ImageRef> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return None;
    }

    // A bare digest / image-ID (`sha256:<hex>`) is NOT a reference. Without
    // this guard it parses as repo "sha256" + tag "<hex>", which docker.io
    // normalizes to "library/sha256" — a nonexistent repository every blob
    // fetch 401s against (the 0.2.9-nydus mirrors EIO incident). containerd's
    // CRI plugin stores such an image-ID record for every pulled image, so
    // these strings genuinely show up where refs are expected.
    if let Some((algo, hex)) = trimmed.split_once(':')
        && matches!(algo, "sha256" | "sha512")
        && hex.len() >= 32
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }

    let (rest, digest) = match trimmed.split_once('@') {
        Some((head, d)) if !d.is_empty() => (head, Some(d.to_string())),
        _ => (trimmed, None),
    };

    let first_slash = rest.find('/');
    let has_registry = match first_slash {
        Some(idx) => {
            let prefix = &rest[..idx];
            prefix.contains('.') || prefix.contains(':') || prefix == "localhost"
        }
        None => false,
    };

    let (host, name_with_tag) = if has_registry {
        let idx = first_slash.unwrap();
        (rest[..idx].to_string(), &rest[idx + 1..])
    } else {
        ("docker.io".to_string(), rest)
    };

    let (name, tag) = match name_with_tag.rsplit_once(':') {
        Some((n, t)) if !t.is_empty() && !t.contains('/') => (n.to_string(), Some(t.to_string())),
        _ => (name_with_tag.to_string(), None),
    };

    if name.is_empty() {
        return None;
    }

    let repo = if host == "docker.io" && !name.contains('/') {
        format!("library/{name}")
    } else {
        name
    };

    let api_host = if host == "docker.io" {
        "registry-1.docker.io".to_string()
    } else {
        host.clone()
    };

    Some(ImageRef {
        host,
        api_host,
        repo,
        tag,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_docker_short_form() {
        let r = parse_image_ref("nginx:latest").unwrap();
        assert_eq!(r.host, "docker.io");
        assert_eq!(r.api_host, "registry-1.docker.io");
        assert_eq!(r.repo, "library/nginx");
        assert_eq!(r.tag.as_deref(), Some("latest"));
    }

    #[test]
    fn parse_full_docker_ref() {
        let r = parse_image_ref("docker.io/thegrandpkizzle/acme-dns:v2.0.0-nydus").unwrap();
        assert_eq!(r.api_host, "registry-1.docker.io");
        assert_eq!(r.repo, "thegrandpkizzle/acme-dns");
        assert_eq!(r.tag.as_deref(), Some("v2.0.0-nydus"));
    }

    #[test]
    fn parse_custom_registry_with_port() {
        let r = parse_image_ref("registry.local:5000/team/svc:1.2.3").unwrap();
        assert_eq!(r.host, "registry.local:5000");
        assert_eq!(r.api_host, "registry.local:5000");
        assert_eq!(r.repo, "team/svc");
    }

    #[test]
    fn parse_with_digest() {
        let r = parse_image_ref("ghcr.io/foo/bar@sha256:deadbeef").unwrap();
        assert_eq!(r.host, "ghcr.io");
        assert_eq!(r.repo, "foo/bar");
        assert_eq!(r.digest.as_deref(), Some("sha256:deadbeef"));
        assert!(r.tag.is_none());
    }

    #[test]
    fn parse_empty_returns_none() {
        assert!(parse_image_ref("").is_none());
        assert!(parse_image_ref("   ").is_none());
    }

    /// REGRESSION (0.2.9-nydus mirrors EIO): a bare image-ID must not parse
    /// into repo "sha256" / "library/sha256" — it is not a reference at all.
    #[test]
    fn parse_bare_digest_returns_none() {
        assert!(
            parse_image_ref(
                "sha256:0c0da3558734bbf673448b752bb6c139cbd3ece8060c6589370280b8ba631d9e"
            )
            .is_none()
        );
        assert!(
            parse_image_ref(
                "sha512:6015a4142a432c74338d5f45f4675dd530b26186fdad2e2377cfb692e9ecd7a3\
                 6015a4142a432c74338d5f45f4675dd530b26186fdad2e2377cfb692e9ecd7a3"
            )
            .is_none()
        );
        // Real refs that merely CONTAIN a digest still parse.
        assert!(parse_image_ref("ghcr.io/foo/bar@sha256:deadbeef").is_some());
        // A genuine repo named "sha256" with a short non-hex tag still parses
        // (the guard requires >=32 hex chars).
        assert!(parse_image_ref("sha256:latest").is_some());
    }
}
