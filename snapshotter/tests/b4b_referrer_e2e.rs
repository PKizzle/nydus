//! B4b end-to-end: materialize a referrer-published nydus bootstrap from a live
//! OCI registry, exercising both digest shapes (artifact-manifest and direct
//! bootstrap-blob). Gated on `B4B_E2E=1` + a running registry fixture, so it is
//! a no-op in normal CI. Driven by the coordinator in the OrbStack Linux runtime
//! (see the fixture-build script). Inputs via env:
//!   B4B_REGISTRY  e.g. nydus-registry:5000
//!   B4B_REPO      e.g. b4bimg
//!   B4B_BOOT_SHA  hex sha256 of the bootstrap blob (direct-digest case)
//!   B4B_ART_SHA   hex sha256 of the artifact manifest (referrers-index case)
//!   B4B_EXPECTED  path to the known-good bootstrap file for byte comparison

use std::path::Path;

use nydus_snapshotter::config::{RegistryBackendConfig, SnapshotterConfig};
use nydus_snapshotter::source::referrer::materialize_bootstrap_blocking;

fn skip_verify_config() -> SnapshotterConfig {
    let mut config = SnapshotterConfig::default();
    // Accept the self-signed HTTPS registry (referrer client honors
    // backends.registry.skip_verify). RegistryBackendConfig has no Default, so
    // construct it explicitly.
    config.backends.registry = Some(RegistryBackendConfig {
        mirrors: Vec::new(),
        skip_verify: true,
        ca_cert_files: Vec::new(),
        plain_http: false,
        request_timeout: "30s".to_string(),
    });
    config
}

#[test]
fn materialize_referrer_bootstrap_both_digest_shapes() {
    if std::env::var("B4B_E2E").as_deref() != Ok("1") {
        eprintln!("skip: set B4B_E2E=1 + registry fixture env to run");
        return;
    }
    let registry = std::env::var("B4B_REGISTRY").expect("B4B_REGISTRY");
    let repo = std::env::var("B4B_REPO").expect("B4B_REPO");
    let boot_sha = std::env::var("B4B_BOOT_SHA").expect("B4B_BOOT_SHA");
    let art_sha = std::env::var("B4B_ART_SHA").expect("B4B_ART_SHA");
    let expected_path = std::env::var("B4B_EXPECTED").expect("B4B_EXPECTED");

    let expected = std::fs::read(&expected_path).expect("read expected bootstrap");
    let image_ref = format!("{registry}/{repo}:latest");
    let config = skip_verify_config();

    // Case 1 — artifact-manifest digest (referrers-index path): materialize must
    // GET the manifest, select the nydus-bootstrap layer, download THAT blob.
    let dir1 = tempfile::tempdir().expect("tempdir");
    let p1 = materialize_bootstrap_blocking(
        &image_ref,
        &format!("sha256:{art_sha}"),
        &config,
        dir1.path(),
    )
    .expect("materialize (artifact-manifest case)");
    let got1 = std::fs::read(&p1).expect("read materialized bootstrap 1");
    assert_eq!(
        got1, expected,
        "artifact-manifest case: bootstrap bytes mismatch"
    );
    eprintln!("B4B-E2E: artifact-manifest case OK -> {}", p1.display());

    // Case 2 — direct bootstrap-blob digest (manifest-layers path): manifest GET
    // 404s, falls back to the blob endpoint.
    let dir2 = tempfile::tempdir().expect("tempdir");
    let p2 = materialize_bootstrap_blocking(
        &image_ref,
        &format!("sha256:{boot_sha}"),
        &config,
        dir2.path(),
    )
    .expect("materialize (direct-blob case)");
    let got2 = std::fs::read(&p2).expect("read materialized bootstrap 2");
    assert_eq!(got2, expected, "direct-blob case: bootstrap bytes mismatch");
    eprintln!("B4B-E2E: direct-blob case OK -> {}", p2.display());

    // Idempotent reuse: a second call in dir2 must return the same path without
    // re-fetching.
    let _: &Path = p2.as_path();
    let p2b = materialize_bootstrap_blocking(
        &image_ref,
        &format!("sha256:{boot_sha}"),
        &config,
        dir2.path(),
    )
    .expect("materialize (cached)");
    assert_eq!(p2, p2b, "idempotent reuse returned a different path");
    eprintln!("B4B-E2E-PASS: both digest shapes materialized the correct bootstrap");
}
