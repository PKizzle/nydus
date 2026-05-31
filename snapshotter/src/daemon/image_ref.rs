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
}
