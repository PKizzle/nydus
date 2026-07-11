// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! OCI image reference parsing.
//!
//! Splits a reference like `docker.io/library/nginx:latest@sha256:abc...` into
//! `(host, repo, tag, digest)` and applies the well-known `docker.io` ->
//! `registry-1.docker.io` API-host rewrite. Self-contained port of the
//! snapshotter's `daemon/image_ref.rs` parser.

use anyhow::{Result, bail};
use std::fmt;

/// Parsed components of an OCI image reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageReference {
    /// Registry host as embedded in the reference (e.g. `docker.io`,
    /// `registry.local:5000`).
    pub host: String,
    /// Registry host used for HTTP requests (e.g. `registry-1.docker.io` for
    /// `docker.io`; identical to [`host`](Self::host) everywhere else).
    pub api_host: String,
    /// Repository path (e.g. `library/nginx`).
    pub repo: String,
    /// Tag, if present.
    pub tag: Option<String>,
    /// Digest (`sha256:<hex>`), if present.
    pub digest: Option<String>,
}

impl ImageReference {
    /// Parse an image reference into its components.
    ///
    /// Accepts inputs missing the registry host (defaults to `docker.io`) and
    /// missing the repository namespace under `docker.io` (defaults to
    /// `library/`). A first path component counts as a registry host when it
    /// contains a `.` or `:` or equals `localhost`.
    pub fn parse(reference: &str) -> Result<Self> {
        let trimmed = reference.trim();
        if trimmed.is_empty() {
            bail!("empty image reference");
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
            Some((n, t)) if !t.is_empty() && !t.contains('/') => {
                (n.to_string(), Some(t.to_string()))
            }
            _ => (name_with_tag.to_string(), None),
        };

        if name.is_empty() {
            bail!("image reference {reference:?} has no repository name");
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

        Ok(Self {
            host,
            api_host,
            repo,
            tag,
            digest,
        })
    }

    /// The reference to use in `/v2/<repo>/manifests/<reference>` requests:
    /// the digest when present (immutable, preferred), else the tag, else the
    /// conventional default tag `latest`.
    pub fn manifest_reference(&self) -> &str {
        if let Some(digest) = self.digest.as_deref() {
            digest
        } else if let Some(tag) = self.tag.as_deref() {
            tag
        } else {
            "latest"
        }
    }
}

impl fmt::Display for ImageReference {
    /// Canonical form: `host/repo[:tag][@digest]`. Short docker.io inputs
    /// display in normalized form (`docker.io/library/nginx:latest`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.host, self.repo)?;
        if let Some(tag) = self.tag.as_deref() {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = self.digest.as_deref() {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_docker_short_form() {
        let r = ImageReference::parse("nginx:latest").unwrap();
        assert_eq!(r.host, "docker.io");
        assert_eq!(r.api_host, "registry-1.docker.io");
        assert_eq!(r.repo, "library/nginx");
        assert_eq!(r.tag.as_deref(), Some("latest"));
        assert!(r.digest.is_none());
    }

    #[test]
    fn parse_full_docker_ref() {
        let r = ImageReference::parse("docker.io/thegrandpkizzle/acme-dns:v2.0.0-nydus").unwrap();
        assert_eq!(r.api_host, "registry-1.docker.io");
        assert_eq!(r.repo, "thegrandpkizzle/acme-dns");
        assert_eq!(r.tag.as_deref(), Some("v2.0.0-nydus"));
    }

    #[test]
    fn parse_custom_registry_with_port() {
        let r = ImageReference::parse("registry.local:5000/team/svc:1.2.3").unwrap();
        assert_eq!(r.host, "registry.local:5000");
        assert_eq!(r.api_host, "registry.local:5000");
        assert_eq!(r.repo, "team/svc");
        assert_eq!(r.tag.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn parse_with_digest() {
        let r = ImageReference::parse("ghcr.io/foo/bar@sha256:deadbeef").unwrap();
        assert_eq!(r.host, "ghcr.io");
        assert_eq!(r.repo, "foo/bar");
        assert_eq!(r.digest.as_deref(), Some("sha256:deadbeef"));
        assert!(r.tag.is_none());
        assert_eq!(r.manifest_reference(), "sha256:deadbeef");
    }

    #[test]
    fn parse_tag_and_digest() {
        let r = ImageReference::parse("registry.local:5000/app:1.0@sha256:abc").unwrap();
        assert_eq!(r.tag.as_deref(), Some("1.0"));
        assert_eq!(r.digest.as_deref(), Some("sha256:abc"));
        // Digest wins for manifest requests (immutable).
        assert_eq!(r.manifest_reference(), "sha256:abc");
    }

    #[test]
    fn parse_localhost_registry() {
        let r = ImageReference::parse("localhost/foo:1").unwrap();
        assert_eq!(r.host, "localhost");
        assert_eq!(r.repo, "foo");
    }

    #[test]
    fn parse_empty_is_error() {
        assert!(ImageReference::parse("").is_err());
        assert!(ImageReference::parse("   ").is_err());
    }

    #[test]
    fn manifest_reference_defaults_to_latest() {
        let r = ImageReference::parse("ghcr.io/foo/bar").unwrap();
        assert!(r.tag.is_none());
        assert_eq!(r.manifest_reference(), "latest");
    }

    #[test]
    fn display_is_canonical_and_reparses() {
        let cases = [
            ("nginx:latest", "docker.io/library/nginx:latest"),
            (
                "registry.local:5000/team/svc:1.2.3",
                "registry.local:5000/team/svc:1.2.3",
            ),
            (
                "ghcr.io/foo/bar@sha256:deadbeef",
                "ghcr.io/foo/bar@sha256:deadbeef",
            ),
        ];
        for (input, want) in cases {
            let parsed = ImageReference::parse(input).unwrap();
            assert_eq!(parsed.to_string(), want);
            assert_eq!(ImageReference::parse(want).unwrap(), parsed);
        }
    }
}
