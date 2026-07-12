// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! P4e ecosystem-loop e2e: prove the RUST NYDUSIFY push side and the
//! SNAPSHOTTER consume side agree on the referrer-artifact contract.
//!
//! Unlike `b4b_referrer_e2e.rs` (which is handed explicit digests), this test
//! is DISCOVERY-DRIVEN: it starts from the ORIGINAL image reference — exactly
//! what `prepare()` has — and exercises the full consume path:
//!
//!   1. `detect_referrer_with_config(<original ref>)` must classify the image
//!      as `NydusRafs` by finding the artifact nydusify pushed (referrers API
//!      or the `sha256-<subject>` fallback tag) and yield a bootstrap digest.
//!   2. `materialize_bootstrap_blocking` must fetch + sha256-verify the
//!      bootstrap through the artifact-manifest walk.
//!   3. The bytes must equal the bootstrap nydusify produced locally.
//!
//! Gated on `P4E_E2E=1` + a fixture pushed by `misc/p4e-ecosystem-loop-test.sh`:
//!   P4E_IMAGE_REF        the ORIGINAL image ref, e.g. nydus-registry:5000/loop/app:v1
//!   P4E_MATERIALIZE_DIR  dir to materialize into (harness mounts from here)
//!   P4E_EXPECTED         optional: known-good bootstrap for byte comparison
//!
//! The harness's serve leg (nydusd registry-backend mount + file comparison
//! against the source rootfs) is the stronger, non-circular assertion; this
//! test proves the DISCOVERY contract and hands the bootstrap over.

use nydus_snapshotter::config::{RegistryBackendConfig, SnapshotterConfig};
use nydus_snapshotter::source::referrer::{
    ImageType, detect_referrer_with_config, materialize_bootstrap_blocking,
};

fn skip_verify_config() -> SnapshotterConfig {
    let mut config = SnapshotterConfig::default();
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
fn discovery_driven_detect_and_materialize_from_original_ref() {
    if std::env::var("P4E_E2E").as_deref() != Ok("1") {
        eprintln!("skip: set P4E_E2E=1 + fixture env (see misc/p4e-ecosystem-loop-test.sh)");
        return;
    }
    let image_ref = std::env::var("P4E_IMAGE_REF").expect("P4E_IMAGE_REF");
    let out_dir = std::env::var("P4E_MATERIALIZE_DIR").expect("P4E_MATERIALIZE_DIR");
    std::fs::create_dir_all(&out_dir).expect("create materialize dir");
    let config = skip_verify_config();

    // 1. Discovery from the ORIGINAL ref — the exact call prepare() makes.
    let info = compio::runtime::Runtime::new()
        .expect("compio runtime")
        .block_on(detect_referrer_with_config(&image_ref, &config))
        .expect("referrer detection must succeed against the live registry");
    assert_eq!(
        info.image_type,
        ImageType::NydusRafs,
        "nydusify --with-referrer artifact must be detected as NydusRafs from the original ref"
    );
    let bootstrap_digest = info
        .bootstrap_digest
        .expect("detection must yield a bootstrap digest");
    eprintln!("P4E-E2E: detected NydusRafs via referrers, digest={bootstrap_digest}");

    // 2. Materialize through the artifact-manifest walk into the harness dir.
    let path = materialize_bootstrap_blocking(
        &image_ref,
        &bootstrap_digest,
        &config,
        std::path::Path::new(&out_dir),
    )
    .expect("materialize (artifact-manifest walk)");
    eprintln!("P4E-E2E: materialized bootstrap at {}", path.display());

    // 3. Optional byte-compare when the harness kept nydusify's local copy;
    //    the harness's nydusd serve leg is the primary content assertion.
    if let Ok(expected_path) = std::env::var("P4E_EXPECTED") {
        let expected = std::fs::read(&expected_path).expect("read expected bootstrap");
        let got = std::fs::read(&path).expect("read materialized bootstrap");
        assert_eq!(
            got, expected,
            "materialized bootstrap must byte-match what nydusify produced"
        );
    }
    eprintln!("P4E-E2E-PASS: discovery contract holds (detect -> materialize)");
}
