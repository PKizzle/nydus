//! Referrer trust end-to-end against a live OCI registry: detection, cosign
//! signature verification, subject and blob binding, then materialization.
//!
//! Skipped unless both are set:
//!   REFERRER_E2E_REGISTRY  plain-HTTP registry, e.g. 127.0.0.1:5000
//!   NYDUS_IMAGE            nydus-image binary that builds the bootstrap
//!
//! The test pushes everything itself (subject image, referrer artifact under
//! the fallback tag, cosign-layout signature), so `misc/referrer/trust-e2e.sh`
//! only has to start the registry.

mod common;

use common::{MANIFEST, Registry, key};
use nydus_snapshotter::config::{
    ReferrerTrustRule, ReferrerVerifier, RegistryBackendConfig, SnapshotterConfig,
};
use nydus_snapshotter::source::referrer::{
    ImageType, ReferrerInfo, detect_referrer_with_config, materialize_bootstrap_blocking,
};
use registry_client::{RegistryClient, RegistryClientOptions};
use serde_json::json;
use std::path::Path;

fn open_registry(endpoint: &str, repo: &str) -> Registry {
    let client = RegistryClient::new(
        endpoint,
        RegistryClientOptions {
            plain_http: true,
            ..RegistryClientOptions::default()
        },
    )
    .unwrap();
    Registry {
        client,
        repo: repo.to_string(),
    }
}

fn build_nydus_image(nydus_image: &str, work: &Path) -> (Vec<u8>, Vec<u8>) {
    let src = work.join("src");
    let out = work.join("out");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(src.join("hello.txt"), b"referrer trust e2e\n".repeat(512)).unwrap();
    let boot = work.join("bootstrap");
    let status = std::process::Command::new(nydus_image)
        .args(["create", "--fs-version", "6", "--compressor", "none", "-B"])
        .arg(&boot)
        .arg("-D")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap();
    assert!(status.success(), "nydus-image create");
    let blob = std::fs::read_dir(&out).unwrap().next().unwrap().unwrap();
    (
        std::fs::read(&boot).unwrap(),
        std::fs::read(blob.path()).unwrap(),
    )
}

fn config(registry: &str, repo: &str, pem: &str) -> SnapshotterConfig {
    let mut config = SnapshotterConfig::default();
    config.snapshotter.features.referrer_detect = true;
    config.snapshotter.referrer_trust.rules = vec![ReferrerTrustRule {
        scope: format!("{registry}/{repo}"),
        verifier: ReferrerVerifier::CosignKey,
        public_keys: vec![pem.to_string()],
    }];
    config.backends.registry = Some(RegistryBackendConfig {
        mirrors: Vec::new(),
        skip_verify: false,
        ca_cert_files: Vec::new(),
        plain_http: true,
        request_timeout: "30s".to_string(),
    });
    config
}

fn rejected(result: anyhow::Result<std::path::PathBuf>, why: &str) {
    let err = format!("{:#}", result.expect_err(why));
    assert!(err.contains(why), "expected {why:?}, got: {err}");
    eprintln!("rejected as expected: {err}");
}

#[test]
fn referrer_is_served_only_when_signed_by_a_trusted_key_and_bound() {
    let (Ok(registry), Ok(nydus_image)) = (
        std::env::var("REFERRER_E2E_REGISTRY"),
        std::env::var("NYDUS_IMAGE"),
    ) else {
        eprintln!("skip: set REFERRER_E2E_REGISTRY and NYDUS_IMAGE");
        return;
    };
    let repo = "trust/app".to_string();
    let work = tempfile::tempdir().unwrap();
    let (bootstrap, data) = build_nydus_image(&nydus_image, work.path());
    let (trusted, trusted_pem) = key();
    let (_, other_pem) = key();

    let rt = compio::runtime::Runtime::new().unwrap();
    let (subject, referrer, unbound) = rt.block_on(async {
        let reg = open_registry(&registry, &repo);

        let layer = reg
            .blob(b"plain oci layer", "application/vnd.oci.image.layer.v1.tar+gzip")
            .await;
        let config = reg.config().await;
        let (subject, subject_size) = reg
            .manifest(
                json!({"schemaVersion": 2, "mediaType": MANIFEST, "config": config, "layers": [layer]}),
                Some("v1"),
            )
            .await;

        let data_layer = reg
            .blob(&data, "application/vnd.oci.image.layer.nydus.blob.v1")
            .await;
        let mut boot_layer = reg
            .blob(&bootstrap, "application/vnd.oci.image.layer.nydus.bootstrap.v1")
            .await;
        boot_layer["annotations"] = json!({"containerd.io/snapshot/nydus-bootstrap": "true"});
        let subject_desc = json!({"mediaType": MANIFEST, "digest": subject, "size": subject_size});
        let artifact = |layers: serde_json::Value| {
            json!({
                "schemaVersion": 2, "mediaType": MANIFEST,
                "artifactType": "application/vnd.oci.image.layer.nydus.blob.v1",
                "config": config, "layers": layers, "subject": subject_desc,
            })
        };
        let fallback_tag = subject.replace(':', "-");
        let (referrer, _) = reg
            .manifest(artifact(json!([data_layer, boot_layer])), Some(&fallback_tag))
            .await;
        // Signed, but its layers omit the data blob the bootstrap reads.
        let (unbound, _) = reg.manifest(artifact(json!([boot_layer])), None).await;
        reg.sign(&trusted, &unbound).await;
        (subject, referrer, unbound)
    });

    let image_ref = format!("{registry}/{repo}:v1");
    let cfg = config(&registry, &repo, &trusted_pem);
    let info = rt
        .block_on(detect_referrer_with_config(&image_ref, &cfg))
        .unwrap();
    assert_eq!(info.image_type, ImageType::NydusRafs);
    assert_eq!(info.bootstrap_digest.as_deref(), Some(referrer.as_str()));
    assert_eq!(info.referrer_subject.as_deref(), Some(subject.as_str()));

    let cache = tempfile::tempdir().unwrap();
    let materialize = |info: &ReferrerInfo, cfg: &SnapshotterConfig| {
        materialize_bootstrap_blocking(&image_ref, info, cfg, cache.path())
    };

    rejected(materialize(&info, &cfg), "unsigned");

    // RegistryClient::new needs a current compio runtime.
    rt.block_on(async {
        open_registry(&registry, &repo)
            .sign(&trusted, &referrer)
            .await
    });

    rejected(
        materialize(&info, &config(&registry, &repo, &other_pem)),
        "does not verify with any trusted key",
    );
    rejected(
        materialize(&info, &config(&registry, "other/app", &trusted_pem)),
        "no [snapshotter.referrer_trust] rule matches",
    );
    let unbound_info = ReferrerInfo {
        bootstrap_digest: Some(unbound),
        ..info.clone()
    };
    rejected(materialize(&unbound_info, &cfg), "does not list");
    let replayed = ReferrerInfo {
        referrer_subject: Some(format!("sha256:{}", "0".repeat(64))),
        ..info.clone()
    };
    rejected(materialize(&replayed, &cfg), "is not the image");

    let path = materialize(&info, &cfg).expect("signed, bound referrer is served");
    assert_eq!(std::fs::read(&path).unwrap(), bootstrap);
    eprintln!("served: {}", path.display());

    // Off by default: no referrer lookup at all.
    let mut off = cfg.clone();
    off.snapshotter.features.referrer_detect = false;
    let pinned = format!("{registry}/{repo}@{subject}");
    let info = rt
        .block_on(detect_referrer_with_config(&pinned, &off))
        .unwrap();
    assert_eq!(info.image_type, ImageType::StandardOci);
    eprintln!("REFERRER-TRUST-E2E-PASS");
}
