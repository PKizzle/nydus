// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Trust policy for referrer-published bootstraps.
//!
//! A referrer is attached by anyone who can push to the image's repository, and
//! its bootstrap defines the whole file tree (names, modes, setuid bits, owners,
//! symlinks, range mapping). So a referrer is served only when:
//!
//! 1. a `[[snapshotter.referrer_trust.rules]]` entry matches `<registry>/<repository>`,
//! 2. the referrer manifest carries a **cosign key-based signature** that verifies
//!    with one of that rule's public keys (ECDSA P-256 or Ed25519), and
//! 3. every blob the bootstrap's blob table names is listed in the signed
//!    manifest ([`check_blob_binding`]).
//!
//! Signatures are found by cosign's tag convention: `sha256-<manifest-hex>.sig` in
//! the image's repository, an OCI manifest whose layers are simple-signing
//! payloads (`application/vnd.dev.cosign.simplesigning.v1+json`) signed in the
//! `dev.cosignproject.cosign/signature` annotation. cosign's OCI 1.1 referrer
//! storage and its sigstore-bundle format are not consulted, nor are keyless
//! (Fulcio/Rekor) and notation signatures: a rule naming those verifiers fails
//! closed.

use crate::config::{ReferrerTrustConfig, ReferrerTrustRule, ReferrerVerifier};
use base64::Engine;
use nydus_api::ConfigV2;
use nydus_rafs::metadata::RafsSuper;
use nydus_storage::device::BlobFeatures;
use registry_client::{RegistryClient, RegistryError};
use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519, UnparsedPublicKey};
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::pki_types::pem::PemObject;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

pub const COSIGN_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
pub const COSIGN_SIMPLE_SIGNING_MEDIA_TYPE: &str =
    "application/vnd.dev.cosign.simplesigning.v1+json";
const COSIGN_SIGNATURE_TYPE: &str = "cosign container image signature";
/// Bound on payload fetches per signature manifest, so a hostile one cannot
/// make a Prepare walk thousands of layers.
const MAX_SIGNATURE_LAYERS: usize = 32;

/// DER prefix of a SubjectPublicKeyInfo for an uncompressed P-256 point
/// (id-ecPublicKey, prime256v1, BIT STRING of 66 bytes).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// DER prefix of a SubjectPublicKeyInfo for Ed25519 (id-Ed25519, BIT STRING of 33 bytes).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Why a referrer is not trusted.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("invalid digest {0:?}: expected sha256:<64 lowercase hex>")]
    InvalidDigest(String),
    #[error("no [snapshotter.referrer_trust] rule matches {0}")]
    NoMatchingRule(String),
    #[error("trust rule {scope:?} names verifier {verifier:?}, which is not supported")]
    UnsupportedVerifier {
        scope: String,
        verifier: ReferrerVerifier,
    },
    #[error("invalid scope glob: {0}")]
    InvalidScope(#[source] glob::PatternError),
    #[error("invalid public key: {0}")]
    InvalidKey(&'static str),
    #[error("unsigned: no cosign signature at tag {0}")]
    Unsigned(String),
    #[error("malformed cosign signature: {0}")]
    MalformedSignature(String),
    #[error("signed payload names {signed}, not referrer manifest {expected}")]
    PayloadDigestMismatch { signed: String, expected: String },
    #[error("signature does not verify with any trusted key")]
    UntrustedKey,
    #[error("referrer subject {actual:?} is not the image {expected}")]
    SubjectMismatch {
        expected: String,
        actual: Option<String>,
    },
    #[error("bootstrap references blob {0}, which the referrer manifest does not list")]
    UnboundBlob(String),
    #[error("read the bootstrap blob table")]
    Bootstrap(#[source] nydus_rafs::RafsError),
    #[error("fetch cosign signature")]
    Registry(#[source] RegistryError),
}

/// True for `sha256:<64 lowercase hex>`, the only digest form that may become a
/// path, a file name or a tag.
pub fn is_canonical_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

pub fn validate_digest(digest: &str) -> Result<&str, TrustError> {
    if is_canonical_digest(digest) {
        Ok(digest)
    } else {
        Err(TrustError::InvalidDigest(digest.to_string()))
    }
}

/// A trusted signing key.
#[derive(Debug)]
pub enum PublicKey {
    /// Uncompressed SEC1 point.
    P256(Vec<u8>),
    Ed25519(Vec<u8>),
}

impl PublicKey {
    /// Parse a PEM `PUBLIC KEY` (SubjectPublicKeyInfo), as `cosign generate-key-pair` writes.
    pub fn from_pem(pem: &str) -> Result<Self, TrustError> {
        let spki = SubjectPublicKeyInfoDer::from_pem_slice(pem.as_bytes())
            .map_err(|_| TrustError::InvalidKey("not a PEM PUBLIC KEY"))?;
        let der: &[u8] = spki.as_ref();
        if let Some(point) = der.strip_prefix(&P256_SPKI_PREFIX[..])
            && point.len() == 65
        {
            return Ok(Self::P256(point.to_vec()));
        }
        if let Some(key) = der.strip_prefix(&ED25519_SPKI_PREFIX[..])
            && key.len() == 32
        {
            return Ok(Self::Ed25519(key.to_vec()));
        }
        Err(TrustError::InvalidKey(
            "only ECDSA P-256 and Ed25519 keys are supported",
        ))
    }

    fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::P256(point) => UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point),
            Self::Ed25519(key) => UnparsedPublicKey::new(&ED25519, key),
        }
        .verify(message, signature)
        .is_ok()
    }
}

/// Check a rule at config load, so a typo in a key or glob stops startup
/// instead of silently refusing every referrer.
pub fn validate_rule(rule: &ReferrerTrustRule) -> Result<(), TrustError> {
    glob::Pattern::new(&rule.scope).map_err(TrustError::InvalidScope)?;
    if rule.verifier == ReferrerVerifier::CosignKey {
        if rule.public_keys.is_empty() {
            return Err(TrustError::InvalidKey(
                "a cosign-key rule needs public_keys",
            ));
        }
        for key in &rule.public_keys {
            PublicKey::from_pem(key)?;
        }
    }
    Ok(())
}

/// The first rule whose scope glob matches `name` (`<registry>/<repository>`).
/// `*` stays within one path segment; `**` spans segments.
pub fn matching_rule<'a>(
    policy: &'a ReferrerTrustConfig,
    name: &str,
) -> Result<&'a ReferrerTrustRule, TrustError> {
    let opts = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    for rule in &policy.rules {
        let pattern = glob::Pattern::new(&rule.scope).map_err(TrustError::InvalidScope)?;
        if pattern.matches_with(name, opts) {
            return Ok(rule);
        }
    }
    Err(TrustError::NoMatchingRule(name.to_string()))
}

/// cosign's signature tag for a manifest digest.
pub fn signature_tag(manifest_digest: &str) -> Result<String, TrustError> {
    Ok(format!(
        "{}.sig",
        validate_digest(manifest_digest)?.replace(':', "-")
    ))
}

#[derive(Deserialize)]
struct SimpleSigning {
    critical: Critical,
}

#[derive(Deserialize)]
struct Critical {
    image: SignedImage,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct SignedImage {
    #[serde(rename = "docker-manifest-digest")]
    docker_manifest_digest: String,
}

/// Verify one cosign simple-signing payload: the base64 `signature` must verify
/// over the exact payload bytes with one of `keys`, and the payload must name
/// `manifest_digest`.
pub fn verify_simple_signing(
    payload: &[u8],
    signature_b64: &str,
    manifest_digest: &str,
    keys: &[PublicKey],
) -> Result<(), TrustError> {
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|e| TrustError::MalformedSignature(format!("signature is not base64: {e}")))?;
    if !keys.iter().any(|key| key.verifies(payload, &signature)) {
        return Err(TrustError::UntrustedKey);
    }
    // Parse only after the signature holds: the payload is attacker input until then.
    let signed: SimpleSigning = serde_json::from_slice(payload)
        .map_err(|e| TrustError::MalformedSignature(format!("payload: {e}")))?;
    if signed.critical.kind != COSIGN_SIGNATURE_TYPE {
        return Err(TrustError::MalformedSignature(format!(
            "payload type {:?}",
            signed.critical.kind
        )));
    }
    if signed.critical.image.docker_manifest_digest != manifest_digest {
        return Err(TrustError::PayloadDigestMismatch {
            signed: signed.critical.image.docker_manifest_digest,
            expected: manifest_digest.to_string(),
        });
    }
    Ok(())
}

#[derive(Deserialize)]
struct SignatureManifest {
    #[serde(default)]
    layers: Vec<SignatureLayer>,
}

#[derive(Deserialize)]
struct SignatureLayer {
    digest: String,
    #[serde(default, rename = "mediaType")]
    media_type: String,
    #[serde(default)]
    annotations: HashMap<String, String>,
}

/// Decide whether the referrer manifest `manifest_digest` in `repo` is signed by
/// a key the policy trusts for `name` (`<registry>/<repository>`).
pub async fn verify_referrer(
    client: &RegistryClient,
    repo: &str,
    name: &str,
    manifest_digest: &str,
    policy: &ReferrerTrustConfig,
) -> Result<(), TrustError> {
    let rule = matching_rule(policy, name)?;
    if rule.verifier != ReferrerVerifier::CosignKey {
        return Err(TrustError::UnsupportedVerifier {
            scope: rule.scope.clone(),
            verifier: rule.verifier,
        });
    }
    let keys = rule
        .public_keys
        .iter()
        .map(|pem| PublicKey::from_pem(pem))
        .collect::<Result<Vec<_>, _>>()?;
    let tag = signature_tag(manifest_digest)?;
    let fetched = match client.get_manifest(repo, &tag).await {
        Ok(fetched) => fetched,
        Err(RegistryError::NotFound { .. }) => return Err(TrustError::Unsigned(tag)),
        Err(e) => return Err(TrustError::Registry(e)),
    };
    let manifest: SignatureManifest = serde_json::from_slice(&fetched.bytes)
        .map_err(|e| TrustError::MalformedSignature(format!("signature manifest: {e}")))?;
    let mut outcome = TrustError::Unsigned(tag);
    for layer in manifest
        .layers
        .iter()
        .filter(|l| l.media_type == COSIGN_SIMPLE_SIGNING_MEDIA_TYPE)
        .take(MAX_SIGNATURE_LAYERS)
    {
        let Some(signature) = layer.annotations.get(COSIGN_SIGNATURE_ANNOTATION) else {
            continue;
        };
        let digest = validate_digest(&layer.digest)?;
        let payload = client
            .get_blob(repo, digest)
            .await
            .map_err(TrustError::Registry)?;
        match verify_simple_signing(&payload, signature, manifest_digest, &keys) {
            Ok(()) => return Ok(()),
            Err(e) => outcome = e,
        }
    }
    Err(outcome)
}

/// Every blob the bootstrap reads must be one the signed manifest lists
/// (`allowed` holds bare hex digests): a signature over the manifest says
/// nothing about blobs it does not name. zran blobs also fetch a separate
/// index blob, named by its meta digest, which must be listed too.
pub fn check_blob_binding(bootstrap: &Path, allowed: &HashSet<String>) -> Result<(), TrustError> {
    let (rs, _) = RafsSuper::load_from_file(bootstrap, Arc::new(ConfigV2::default()), false)
        .map_err(TrustError::Bootstrap)?;
    for blob in rs.superblock.get_blob_infos() {
        let mut ids = vec![blob.raw_blob_id().to_string()];
        if blob.has_feature(BlobFeatures::SEPARATE)
            && !blob.has_feature(BlobFeatures::INLINED_FS_META)
        {
            ids.push(hex::encode(blob.blob_meta_digest()));
        }
        if let Some(id) = ids.into_iter().find(|id| !allowed.contains(id)) {
            return Err(TrustError::UnboundBlob(id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
    use sha2::Digest as _;

    fn pem(der: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
    }

    fn p256_key() -> (EcdsaKeyPair, String) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let spki = [&P256_SPKI_PREFIX[..], pair.public_key().as_ref()].concat();
        (pair, pem(&spki))
    }

    /// The payload `cosign sign` writes for a manifest digest.
    fn payload(digest: &str) -> Vec<u8> {
        format!(
            r#"{{"critical":{{"identity":{{"docker-reference":"registry.test/app"}},"image":{{"docker-manifest-digest":"{digest}"}},"type":"cosign container image signature"}},"optional":null}}"#
        )
        .into_bytes()
    }

    fn sign(pair: &EcdsaKeyPair, payload: &[u8]) -> String {
        let sig = pair.sign(&SystemRandom::new(), payload).unwrap();
        base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
    }

    fn digest() -> String {
        format!("sha256:{}", "ab".repeat(32))
    }

    #[test]
    fn cosign_p256_signature_verifies_only_for_its_key_digest_and_bytes() {
        let (pair, pem) = p256_key();
        let keys = [PublicKey::from_pem(&pem).unwrap()];
        let body = payload(&digest());
        let sig = sign(&pair, &body);

        verify_simple_signing(&body, &sig, &digest(), &keys).expect("valid signature");

        let (_, other) = p256_key();
        let wrong = [PublicKey::from_pem(&other).unwrap()];
        assert!(matches!(
            verify_simple_signing(&body, &sig, &digest(), &wrong),
            Err(TrustError::UntrustedKey)
        ));

        let other_digest = format!("sha256:{}", "cd".repeat(32));
        assert!(matches!(
            verify_simple_signing(&body, &sig, &other_digest, &keys),
            Err(TrustError::PayloadDigestMismatch { .. })
        ));

        let mut tampered = body.clone();
        let at = tampered.len() - 6;
        tampered[at] = b'X';
        assert!(matches!(
            verify_simple_signing(&tampered, &sig, &digest(), &keys),
            Err(TrustError::UntrustedKey)
        ));
    }

    #[test]
    fn cosign_ed25519_signature_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let spki = [&ED25519_SPKI_PREFIX[..], pair.public_key().as_ref()].concat();
        let keys = [PublicKey::from_pem(&pem(&spki)).unwrap()];
        let body = payload(&digest());
        let sig = base64::engine::general_purpose::STANDARD.encode(pair.sign(&body).as_ref());
        verify_simple_signing(&body, &sig, &digest(), &keys).expect("valid ed25519 signature");
    }

    fn rule(scope: &str, verifier: ReferrerVerifier, keys: Vec<String>) -> ReferrerTrustRule {
        ReferrerTrustRule {
            scope: scope.to_string(),
            verifier,
            public_keys: keys,
        }
    }

    #[test]
    fn first_matching_scope_decides_and_star_stays_in_one_segment() {
        let (_, pem) = p256_key();
        let policy = ReferrerTrustConfig {
            rules: vec![
                rule(
                    "ghcr.io/acme/*",
                    ReferrerVerifier::CosignKey,
                    vec![pem.clone()],
                ),
                rule("ghcr.io/**", ReferrerVerifier::Notation, vec![]),
            ],
        };
        assert_eq!(
            matching_rule(&policy, "ghcr.io/acme/app").unwrap().scope,
            "ghcr.io/acme/*"
        );
        assert_eq!(
            matching_rule(&policy, "ghcr.io/acme/team/app")
                .unwrap()
                .scope,
            "ghcr.io/**"
        );
        assert!(matches!(
            matching_rule(&policy, "docker.io/library/nginx"),
            Err(TrustError::NoMatchingRule(_))
        ));
        assert!(validate_rule(&policy.rules[0]).is_ok());
        assert!(validate_rule(&rule("x/*", ReferrerVerifier::CosignKey, vec![])).is_err());
        assert!(
            validate_rule(&rule(
                "x/*",
                ReferrerVerifier::CosignKey,
                vec!["-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n".into()]
            ))
            .is_err()
        );
    }

    #[test]
    fn canonical_digests_only() {
        assert!(is_canonical_digest(&digest()));
        for bad in [
            format!("sha256:{}", "AB".repeat(32)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha512:{}", "a".repeat(64)),
            "sha256:../../etc/passwd".to_string(),
            "a".repeat(64),
        ] {
            assert!(!is_canonical_digest(&bad), "{bad}");
        }
        assert_eq!(
            signature_tag(&digest()).unwrap(),
            format!("sha256-{}.sig", "ab".repeat(32))
        );
    }

    fn fixture_bootstrap() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/texture/bootstrap/rafs-v6-2.2.boot")
    }

    #[test]
    fn bootstrap_naming_an_unlisted_blob_is_rejected() {
        // The fixture's blob table names exactly this blob.
        let listed = "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef";
        let foreign: HashSet<String> = ["cd".repeat(32)].into();
        assert!(matches!(
            check_blob_binding(&fixture_bootstrap(), &foreign),
            Err(TrustError::UnboundBlob(id)) if id == listed
        ));
        let allowed: HashSet<String> = [listed.to_string()].into();
        check_blob_binding(&fixture_bootstrap(), &allowed).expect("listed blob binds");
    }

    /// A zran bootstrap reads the gzip layer and its separate index blob; both
    /// must be listed. Needs a nydus-image binary (NYDUS_IMAGE), so it is a
    /// no-op without one.
    #[test]
    fn zran_bootstrap_binds_to_layer_and_index_blob() {
        let Ok(nydus_image) = std::env::var("NYDUS_IMAGE") else {
            eprintln!("skip: set NYDUS_IMAGE");
            return;
        };
        let layer = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/texture/zran/zran-two-streams.tar.gz");
        let work = tempfile::tempdir().unwrap();
        let (boot, out) = (work.path().join("bootstrap"), work.path().join("out"));
        std::fs::create_dir_all(&out).unwrap();
        let args = crate::local_accel::targz_ref_args(&layer, &boot, &out);
        let status = std::process::Command::new(nydus_image)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
        let index: Vec<String> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(index.len(), 1, "one zran index blob: {index:?}");
        let gz = hex::encode(sha2::Sha256::digest(std::fs::read(&layer).unwrap()));

        let all: HashSet<String> = [gz.clone(), index[0].clone()].into();
        check_blob_binding(&boot, &all).expect("layer + index blob bind");
        assert!(matches!(
            check_blob_binding(&boot, &[gz].into()),
            Err(TrustError::UnboundBlob(id)) if id == index[0]
        ));
    }
}
