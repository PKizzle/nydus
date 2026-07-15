// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! TLS configuration for registries signed by a private CA.
//!
//! cyper's `use_rustls_default()` trusts the platform verifier's roots only;
//! a registry behind a private CA then fails the handshake unless TLS
//! verification is disabled entirely. [`client_config_with_extra_roots`]
//! builds a config that trusts the platform roots **plus** operator-supplied
//! PEM roots, so `ca_cert_files` never has to degrade into `skip_verify`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};

/// Build a rustls `ClientConfig` that trusts the platform verifier's roots
/// plus every certificate in `ca_cert_files` (PEM, possibly multiple
/// certificates per file). A file yielding zero certificates is an error —
/// silently ignoring it would report handshake failures far from the typo
/// that caused them.
///
/// The config mirrors what cyper builds for `use_rustls_default()` (platform
/// verifier, ring provider, ALPN `h2` + `http/1.1`) so behaviour differs only
/// by the extra roots. ALPN must be set here: cyper passes a custom config
/// through untouched, and omitting it silently downgrades HTTP/2 negotiation.
pub fn client_config_with_extra_roots(
    ca_cert_files: &[PathBuf],
) -> Result<Arc<rustls::ClientConfig>> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let mut extra_roots: Vec<CertificateDer<'static>> = Vec::new();
    for path in ca_cert_files {
        let before = extra_roots.len();
        let certs = CertificateDer::pem_file_iter(path)
            .with_context(|| format!("open CA cert file {}", path.display()))?;
        for cert in certs {
            extra_roots
                .push(cert.with_context(|| format!("parse CA cert file {}", path.display()))?);
        }
        if extra_roots.len() == before {
            bail!("no CA certificates found in {}", path.display());
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        rustls_platform_verifier::Verifier::new_with_extra_roots(extra_roots, provider.clone())
            .context("build platform certificate verifier with extra CA roots")?;

    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("select rustls protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Genuine throwaway self-signed EC P-256 certificate (same fixture as
    /// the snapshotter's peer-mirror TLS tests) — the platform verifier
    /// DER-decodes extra roots, so the material must parse for real.
    const TEST_CA_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIBljCCAT2gAwIBAgIUH2CY6EpcCSul24kgqnvRpR867GAwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWbnlkdXMtcGVlci1taXJyb3ItdGVzdDAeFw0yNjA3MTUwMDQ1
NDFaFw00NjA3MTAwMDQ1NDFaMCExHzAdBgNVBAMMFm55ZHVzLXBlZXItbWlycm9y
LXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR6ofTJvnpenmDK8aFi8wcE
GvWJ03vGhxeVcetw/dA4TnmDJDPwl26sgyeAe4VzdC7cuFJZ6wKt3mmp3Ic4V0oZ
o1MwUTAdBgNVHQ4EFgQU0PD3NalGUUvozo7afVumnT+IWNwwHwYDVR0jBBgwFoAU
0PD3NalGUUvozo7afVumnT+IWNwwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD
AgNHADBEAiA3gE3QTKdoVKS3mxs9cuZIWjc8o1fZDOzU1bYmKlJtygIgUmvFA6jX
TPkOLsyiOpBJ239612rqvYAon3DdwuFIUmU=
-----END CERTIFICATE-----
";

    #[test]
    fn loads_pem_roots_and_sets_alpn() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, TEST_CA_PEM).unwrap();

        let config = client_config_with_extra_roots(&[ca]).unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn empty_input_still_builds_platform_config() {
        // No extra roots is valid: the platform store alone applies.
        assert!(client_config_with_extra_roots(&[]).is_ok());
    }

    #[test]
    fn garbage_and_certless_files_error() {
        let dir = tempfile::tempdir().unwrap();
        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, "not a pem").unwrap();
        assert!(client_config_with_extra_roots(&[garbage]).is_err());

        let missing = dir.path().join("missing.pem");
        assert!(client_config_with_extra_roots(&[missing]).is_err());
    }
}
