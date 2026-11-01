//! Writes the registry layout `cosign sign --key` produces, for the referrer
//! e2e tests (no cosign binary needed).

#![allow(dead_code)] // each test binary uses a different subset

use base64::Engine;
use registry_client::RegistryClient;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;
use sha2::{Digest, Sha256};

pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// A fresh P-256 key pair and its PEM public key, as `cosign generate-key-pair` writes it.
pub fn key() -> (EcdsaKeyPair, String) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let spki = [&P256_SPKI_PREFIX[..], pair.public_key().as_ref()].concat();
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        b64(&spki)
    );
    (pair, pem)
}

pub struct Registry {
    pub client: RegistryClient,
    pub repo: String,
}

impl Registry {
    pub async fn blob(&self, bytes: &[u8], media_type: &str) -> serde_json::Value {
        let digest = self
            .client
            .push_blob_bytes(&self.repo, bytes)
            .await
            .unwrap();
        json!({"mediaType": media_type, "digest": digest, "size": bytes.len()})
    }

    /// Push a manifest by digest, and under `tag` when given.
    pub async fn manifest(&self, body: serde_json::Value, tag: Option<&str>) -> (String, usize) {
        let bytes = serde_json::to_vec(&body).unwrap();
        let digest = digest(&bytes);
        for reference in [Some(digest.as_str()), tag].into_iter().flatten() {
            self.client
                .push_manifest(&self.repo, reference, MANIFEST, &bytes)
                .await
                .unwrap();
        }
        (digest, bytes.len())
    }

    pub async fn config(&self) -> serde_json::Value {
        self.blob(b"{}", "application/vnd.oci.image.config.v1+json")
            .await
    }

    /// Sign `manifest_digest`: a simple-signing payload layer carrying the
    /// signature annotation, under the `sha256-<hex>.sig` tag.
    pub async fn sign(&self, pair: &EcdsaKeyPair, manifest_digest: &str) {
        let payload = serde_json::to_vec(&json!({
            "critical": {
                "identity": {"docker-reference": self.repo},
                "image": {"docker-manifest-digest": manifest_digest},
                "type": "cosign container image signature"
            },
            "optional": null
        }))
        .unwrap();
        let sig = pair.sign(&SystemRandom::new(), &payload).unwrap();
        let mut layer = self
            .blob(&payload, "application/vnd.dev.cosign.simplesigning.v1+json")
            .await;
        layer["annotations"] = json!({"dev.cosignproject.cosign/signature": b64(sig.as_ref())});
        let tag = format!("{}.sig", manifest_digest.replace(':', "-"));
        let config = self.config().await;
        self.manifest(
            json!({"schemaVersion": 2, "mediaType": MANIFEST, "config": config, "layers": [layer]}),
            Some(&tag),
        )
        .await;
    }
}
