// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! The crate's public error type.
//!
//! `registry-client` is a library, so its public surface returns a typed
//! [`RegistryError`] (`thiserror`) instead of `anyhow::Error`: callers can
//! branch on the variants that matter operationally — a missing manifest/blob
//! ([`RegistryError::NotFound`]), a registry without OCI 1.1 referrers
//! support ([`RegistryError::ReferrersUnsupported`]), auth failures, digest
//! mismatches, timeouts — while everything without a meaningful programmatic
//! distinction flows through the transparent [`RegistryError::Other`]
//! catch-all (`#[from] anyhow::Error`), which keeps internal helpers on
//! `anyhow` and lets the conversion stay incremental.
//!
//! `RegistryError` implements `std::error::Error + Send + Sync + 'static`,
//! so application callers on `anyhow::Result` keep using `?` (and
//! `.context(...)`) unchanged.

use thiserror::Error;

/// Error surface of [`RegistryClient`](crate::RegistryClient)'s public
/// operations.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// The requested resource does not exist (HTTP `404` on a manifest or
    /// blob endpoint). `resource` names what was asked for (e.g.
    /// `manifest team/app:1.2.3`).
    #[error("{resource} not found (HTTP 404)")]
    NotFound {
        /// Human-readable description of the missing resource.
        resource: String,
    },

    /// A non-success HTTP status that is neither a 404 nor an auth failure.
    /// `body` carries a bounded snippet of the response body (may be empty)
    /// for diagnosis — registries put their structured error JSON there.
    #[error("registry request for {resource} failed with HTTP {status}: {body}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Bounded, lossily-decoded response body snippet.
        body: String,
        /// Human-readable description of the requested resource.
        resource: String,
    },

    /// Authentication/authorization failed: the bearer-token dance broke, or
    /// the registry answered `401`/`403` after the credential retry.
    #[error("registry authentication failed: {0}")]
    Auth(String),

    /// Content failed digest verification. Security-relevant: the fetched
    /// bytes are discarded, never surfaced.
    #[error("digest mismatch: expected {expected}, actual {actual}")]
    DigestMismatch {
        /// The digest the content was requested/verified against.
        expected: String,
        /// The digest computed from the received bytes.
        actual: String,
    },

    /// A request or body read exceeded its configured deadline.
    #[error("registry request timed out: {0}")]
    Timeout(String),

    /// The registry does not implement the OCI 1.1 referrers API (`404` on
    /// `/v2/<repo>/referrers/<digest>`; `405`/`400`/`501` shapes from pre-1.1
    /// registries are treated the same). Callers fall back to the
    /// `sha256-<subject-hex>` fallback tag.
    #[error("registry does not support the OCI 1.1 referrers API")]
    ReferrersUnsupported,

    /// Everything else (I/O, TLS setup, URL construction, body parsing, …),
    /// carried with its full `anyhow` context chain.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context as _;

    #[test]
    fn variants_render_operational_context() {
        let e = RegistryError::NotFound {
            resource: "manifest team/app:1".into(),
        };
        assert_eq!(e.to_string(), "manifest team/app:1 not found (HTTP 404)");

        let e = RegistryError::Http {
            status: 502,
            body: "{\"errors\":[]}".into(),
            resource: "blob sha256:abc".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("502"), "{msg}");
        assert!(msg.contains("blob sha256:abc"), "{msg}");

        let e = RegistryError::DigestMismatch {
            expected: "sha256:aaa".into(),
            actual: "sha256:bbb".into(),
        };
        assert!(e.to_string().contains("sha256:aaa"));
        assert!(e.to_string().contains("sha256:bbb"));
    }

    #[test]
    fn anyhow_flows_in_and_out_transparently() {
        // In: anyhow -> RegistryError::Other keeps the context chain visible.
        let source: anyhow::Result<()> = Err(anyhow::anyhow!("root cause")).context("outer step");
        let wrapped: RegistryError = source.unwrap_err().into();
        assert_eq!(wrapped.to_string(), "outer step");
        let chain = format!("{:#}", anyhow::Error::from(wrapped));
        assert!(chain.contains("root cause"), "{chain}");

        // Out: `?` from a RegistryError result inside an anyhow fn compiles
        // and preserves the typed message (RegistryError: Error + Send +
        // Sync + 'static).
        fn caller() -> anyhow::Result<()> {
            fn lib_call() -> Result<(), RegistryError> {
                Err(RegistryError::ReferrersUnsupported)
            }
            lib_call().context("during detection")?;
            Ok(())
        }
        let err = caller().unwrap_err();
        assert!(format!("{err:#}").contains("referrers API"));
    }
}
