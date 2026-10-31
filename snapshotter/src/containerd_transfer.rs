// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Layer backfill through containerd's Transfer service.
//!
//! containerd's unpacker fetches a layer blob only when it has to create that layer's
//! snapshot, so a blob garbage-collected while its snapshot lived on stays missing after
//! later pulls (see [`MissingLayers`]). Node-local acceleration reads those blobs, so before a
//! conversion the snapshotter has containerd itself fetch them: `Transfer.Transfer` from an
//! `OCIRegistry` source to an `ImageStore` destination without unpacks runs containerd's plain
//! fetch over the image and skips content already present. The fetch uses the node's registry
//! hosts directory, so it takes the same mirror route as a CRI pull.
//!
//! containerd keeps no registry credentials for the Transfer service; it asks the client over
//! a `Streaming` stream registered as the resolver's `auth_stream`. Requests are answered from
//! the runtime credential store (`/api/v1/auth`), or anonymously when it has nothing.
//!
//! The destination image record exists only to root the fetched blobs while the transfer
//! runs; it is deleted afterwards, and the real image's manifest keeps the blobs referenced.

use crate::config::ContainerdConfig;
use crate::containerd_api::services::streaming::v1::{
    StreamInit, streaming_client::StreamingClient,
};
use crate::containerd_api::services::transfer::v1::{
    TransferRequest, transfer_client::TransferClient,
};
use crate::containerd_api::types::Platform;
use crate::containerd_api::types::transfer::{
    AuthRequest, AuthResponse, AuthType, ImageStore, OciRegistry, RegistryResolver,
};
use crate::containerd_grpc::ContainerdChannel;
use crate::containerd_lookup::MissingLayers;
use crate::content_store::ContentStoreClient;
use crate::daemon::image_ref::{ImageRef, parse_image_ref};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use futures::future::{Either, select};
use prost::Message;
use prost_types::Any;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, warn};

// containerd's typeurl names protobuf messages by their full name, without the
// `type.googleapis.com/` prefix.
const STREAM_INIT_TYPE: &str = "containerd.services.streaming.v1.StreamInit";
const OCI_REGISTRY_TYPE: &str = "containerd.types.transfer.OCIRegistry";
const IMAGE_STORE_TYPE: &str = "containerd.types.transfer.ImageStore";
const AUTH_REQUEST_TYPE: &str = "containerd.types.transfer.AuthRequest";
const AUTH_RESPONSE_TYPE: &str = "containerd.types.transfer.AuthResponse";

/// Prefix of the temporary image records. Distinct from `nydus.auto-accel.local/`, whose
/// records the reconciler and the peer-mirror self-check treat as sidecars.
const RECORD_PREFIX: &str = "nydus.layer-backfill.local/";

/// Upper bound for one transfer. The conversion worker is serial, so a fetch stuck on an
/// unresponsive registry must not hold every other conversion back.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// What one backfill restored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackfillReport {
    /// Previously missing layer blobs now in the content store.
    pub blobs: usize,
    /// Their combined size.
    pub bytes: u64,
    pub duration: Duration,
}

/// Has containerd fetch an image's missing layer blobs. Cheap to clone.
#[derive(Clone, Debug)]
pub struct LayerBackfill {
    channel: ContainerdChannel,
    content_store: ContentStoreClient,
    hosts_dir: Option<PathBuf>,
}

impl LayerBackfill {
    pub fn new(config: &ContainerdConfig, content_store: ContentStoreClient) -> Self {
        Self {
            channel: ContainerdChannel::new(config.address(), &config.namespace),
            content_store,
            hosts_dir: config.hosts_dir.clone(),
        }
    }

    /// Fetch the blobs `missing` names for `image`. The fetch is pinned to the manifest
    /// digest, so a tag that has moved since the image was pulled cannot change what is
    /// fetched.
    pub async fn fetch(&self, image: &str, missing: &MissingLayers) -> Result<BackfillReport> {
        let started = Instant::now();
        let reference = pinned_reference(image, &missing.manifest)?;
        let record = record_name(&missing.manifest);
        let transfer = compio::time::timeout(TRANSFER_TIMEOUT, self.transfer(&reference, &record))
            .await
            .unwrap_or_else(|_| Err(anyhow!("transfer timed out after {TRANSFER_TIMEOUT:?}")));
        // Delete the record whether or not the transfer succeeded: a partial fetch leaves it
        // behind too, and the real image's manifest is what keeps the fetched blobs.
        let cleanup = self.content_store.images_delete(&record).await;
        transfer.with_context(|| format!("containerd transfer of {reference}"))?;
        cleanup?;

        let mut report = BackfillReport {
            blobs: 0,
            bytes: 0,
            duration: started.elapsed(),
        };
        for digest in &missing.digests {
            if let Ok(meta) = std::fs::metadata(self.content_store.blob_path(digest)) {
                report.blobs += 1;
                report.bytes += meta.len();
            }
        }
        info!(
            image,
            manifest = %missing.manifest,
            blobs = report.blobs,
            bytes = report.bytes,
            duration_ms = report.duration.as_millis() as u64,
            "auto-zran backfilled missing layer blobs"
        );
        Ok(report)
    }

    /// Delete temporary records a crashed backfill left behind. The worker is serial, so
    /// this runs only while no backfill is in flight.
    pub async fn remove_stale_records(&self) -> Result<usize> {
        let mut removed = 0;
        for record in self.content_store.images_list().await? {
            if record.name.starts_with(RECORD_PREFIX) {
                self.content_store.images_delete(&record.name).await?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    async fn transfer(&self, reference: &str, record: &str) -> Result<()> {
        let stream_id = auth_stream_id();
        let (outbound, requests) = async_channel::unbounded::<Any>();
        outbound
            .send(to_any(
                STREAM_INIT_TYPE,
                &StreamInit {
                    id: stream_id.clone(),
                },
            ))
            .await?;
        let mut inbound = StreamingClient::new(self.channel.clone())
            .stream(requests)
            .await
            .map_err(|status| anyhow!("open auth stream: {status}"))?
            .into_inner();
        // containerd acknowledges once the stream is registered under its ID; the transfer
        // must not reference it before that.
        inbound
            .message()
            .await
            .map_err(|status| anyhow!("auth stream handshake: {status}"))?
            .context("auth stream closed during handshake")?;

        let request = transfer_request(reference, record, &stream_id, self.hosts_dir.as_ref());
        let mut client = TransferClient::new(self.channel.clone());
        let transfer = pin!(client.transfer(request));
        let responder = pin!(async {
            while let Some(request) = inbound.message().await? {
                outbound.send(answer_auth(&request)?).await?;
            }
            anyhow::Ok(())
        });
        let result = match select(transfer, responder).await {
            Either::Left((result, _)) => result,
            Either::Right((auth, transfer)) => {
                if let Err(e) = auth {
                    warn!(error = %format!("{e:#}"), "layer backfill auth stream failed");
                }
                transfer.await
            }
        };
        result.map(drop).map_err(|status| anyhow!("{status}"))
    }
}

fn to_any(type_url: &str, message: &impl Message) -> Any {
    Any {
        type_url: type_url.to_string(),
        value: message.encode_to_vec(),
    }
}

fn auth_stream_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "nydus-layer-backfill-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn record_name(manifest: &str) -> String {
    let hex = manifest.strip_prefix("sha256:").unwrap_or(manifest);
    format!("{RECORD_PREFIX}image:{hex}")
}

/// `image` with its tag or digest replaced by `manifest`.
fn pinned_reference(image: &str, manifest: &str) -> Result<String> {
    let ImageRef { host, repo, .. } =
        parse_image_ref(image).with_context(|| format!("parse image reference {image}"))?;
    Ok(format!("{host}/{repo}@{manifest}"))
}

fn host_platform() -> Platform {
    Platform {
        os: std::env::consts::OS.to_string(),
        architecture: registry_client::host_go_arch().to_string(),
        ..Default::default()
    }
}

fn transfer_request(
    reference: &str,
    record: &str,
    auth_stream: &str,
    hosts_dir: Option<&PathBuf>,
) -> TransferRequest {
    let source = OciRegistry {
        reference: reference.to_string(),
        resolver: Some(RegistryResolver {
            auth_stream: auth_stream.to_string(),
            host_dir: hosts_dir
                .map(|dir| dir.to_string_lossy().into_owned())
                .unwrap_or_default(),
            ..Default::default()
        }),
    };
    // No unpacks: containerd only fetches, and only what is not in the content store yet.
    let destination = ImageStore {
        name: record.to_string(),
        platforms: vec![host_platform()],
        ..Default::default()
    };
    TransferRequest {
        source: Some(to_any(OCI_REGISTRY_TYPE, &source)),
        destination: Some(to_any(IMAGE_STORE_TYPE, &destination)),
        options: None,
    }
}

/// Answer one of containerd's credential requests from the runtime credential store.
/// Credential values are never logged.
fn answer_auth(request: &Any) -> Result<Any> {
    if request.type_url != AUTH_REQUEST_TYPE {
        bail!("unexpected message on auth stream: {}", request.type_url);
    }
    let request = AuthRequest::decode(request.value.as_slice()).context("decode AuthRequest")?;
    let stored = parse_image_ref(&request.reference)
        .and_then(|image| crate::daemon::auth::runtime_auth(&image));
    let response = match stored.as_deref().map(decode_docker_auth) {
        Some(Some((username, secret))) => AuthResponse {
            auth_type: AuthType::Credentials as i32,
            username,
            secret,
            expire_at: None,
        },
        Some(None) => {
            warn!(host = %request.host, "stored registry auth is not base64 user:password; fetching anonymously");
            AuthResponse::default()
        }
        None => AuthResponse::default(),
    };
    Ok(to_any(AUTH_RESPONSE_TYPE, &response))
}

/// Split a Docker-style base64 `user:password` value.
fn decode_docker_auth(auth: &str) -> Option<(String, String)> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(auth.trim())
        .ok()?;
    let (user, password) = std::str::from_utf8(&decoded).ok()?.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::auth::{RuntimeAuthRequest, set_runtime_auth};
    use sha2::Digest as _;

    #[test]
    fn transfer_request_pins_the_manifest_and_routes_through_the_hosts_dir() {
        let manifest = format!("sha256:{}", "a".repeat(64));
        let reference = pinned_reference("ghcr.io/org/app:1.2", &manifest).unwrap();
        assert_eq!(reference, format!("ghcr.io/org/app@{manifest}"));
        let record = record_name(&manifest);
        assert_eq!(
            record,
            format!("nydus.layer-backfill.local/image:{}", "a".repeat(64))
        );

        let hosts = PathBuf::from("/etc/containerd/certs.d");
        let request = transfer_request(&reference, &record, "stream-1", Some(&hosts));

        let source = request.source.unwrap();
        assert_eq!(source.type_url, "containerd.types.transfer.OCIRegistry");
        let source = OciRegistry::decode(source.value.as_slice()).unwrap();
        assert_eq!(source.reference, reference);
        let resolver = source.resolver.unwrap();
        assert_eq!(resolver.auth_stream, "stream-1");
        assert_eq!(resolver.host_dir, "/etc/containerd/certs.d");

        let destination = request.destination.unwrap();
        assert_eq!(destination.type_url, "containerd.types.transfer.ImageStore");
        let destination = ImageStore::decode(destination.value.as_slice()).unwrap();
        assert_eq!(destination.name, record);
        assert!(destination.unpacks.is_empty(), "a backfill must not unpack");
        assert_eq!(destination.platforms, vec![host_platform()]);
    }

    #[test]
    fn docker_hub_short_names_pin_to_the_full_reference() {
        assert_eq!(
            pinned_reference("nginx:1.27", "sha256:m").unwrap(),
            "docker.io/library/nginx@sha256:m"
        );
        assert_eq!(
            pinned_reference("docker.io/library/nginx@sha256:old", "sha256:m").unwrap(),
            "docker.io/library/nginx@sha256:m"
        );
    }

    fn auth_request(reference: &str) -> Any {
        to_any(
            AUTH_REQUEST_TYPE,
            &AuthRequest {
                host: "registry.backfill.test".to_string(),
                reference: reference.to_string(),
                wwwauthenticate: vec![],
            },
        )
    }

    fn decode_response(any: Any) -> AuthResponse {
        assert_eq!(any.type_url, "containerd.types.transfer.AuthResponse");
        AuthResponse::decode(any.value.as_slice()).unwrap()
    }

    #[test]
    fn auth_requests_are_answered_from_the_runtime_store() {
        let stored = base64::engine::general_purpose::STANDARD.encode("robot:s3cret");
        set_runtime_auth(vec![RuntimeAuthRequest {
            registry: "registry.backfill.test".to_string(),
            auth: stored,
            expires_in_seconds: None,
        }])
        .unwrap();

        let response = decode_response(
            answer_auth(&auth_request("registry.backfill.test/team/app:1")).unwrap(),
        );
        assert_eq!(response.auth_type, AuthType::Credentials as i32);
        assert_eq!(response.username, "robot");
        assert_eq!(response.secret, "s3cret");
    }

    #[test]
    fn auth_requests_without_stored_credentials_go_anonymous() {
        let response = decode_response(
            answer_auth(&auth_request("unknown.backfill.test/team/app:1")).unwrap(),
        );
        assert_eq!(response.auth_type, AuthType::None as i32);
        assert!(response.username.is_empty() && response.secret.is_empty());
    }

    #[test]
    fn unexpected_stream_messages_are_rejected() {
        let other = to_any(STREAM_INIT_TYPE, &StreamInit { id: "x".into() });
        assert!(answer_auth(&other).is_err());
    }

    /// End to end against a real containerd ≥ 2.0 and a registry requiring basic auth, set up
    /// by misc/containerd-grpc/backfill-test.sh with an image whose layer blobs containerd
    /// skipped (snapshots present, blobs garbage-collected).
    #[test]
    #[ignore = "needs containerd >= 2.0 and a registry; run misc/containerd-grpc/backfill-test.sh"]
    fn backfill_restores_skipped_layer_blobs_through_containerd() {
        let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} unset"));
        let config = ContainerdConfig {
            address: Some(env("BACKFILL_CONTAINERD_ADDRESS").into()),
            namespace: env("BACKFILL_CONTAINERD_NAMESPACE"),
            content_root: Some(env("BACKFILL_CONTENT_ROOT").into()),
            hosts_dir: Some(env("BACKFILL_HOSTS_DIR").into()),
        };
        let image = env("BACKFILL_IMAGE");
        let content_store = ContentStoreClient::new(&config).unwrap();
        let lookup = crate::containerd_lookup::ContainerdLookup::new(content_store.clone());
        let backfill = LayerBackfill::new(&config, content_store.clone());
        let content_root = config.content_root();

        compio::runtime::Runtime::new().unwrap().block_on(async {
            let err = lookup
                .manifest_info(&image, &content_root)
                .await
                .unwrap_err();
            let missing = err
                .downcast_ref::<MissingLayers>()
                .unwrap_or_else(|| panic!("expected missing layers, got {err:#}"))
                .clone();

            // The registry refuses anonymous pulls, and nothing is stored yet.
            let anonymous = format!("{:#}", backfill.fetch(&image, &missing).await.unwrap_err());
            assert!(anonymous.contains("authorization"), "{anonymous}");
            assert!(
                lookup.manifest_info(&image, &content_root).await.is_err(),
                "an unauthorized transfer must not restore blobs"
            );

            set_runtime_auth(vec![RuntimeAuthRequest {
                registry: env("BACKFILL_REGISTRY"),
                auth: env("BACKFILL_AUTH"),
                expires_in_seconds: None,
            }])
            .unwrap();
            let report = backfill.fetch(&image, &missing).await.unwrap();
            assert_eq!(report.blobs, missing.digests.len(), "{report:?}");

            let info = lookup.manifest_info(&image, &content_root).await.unwrap();
            assert_eq!(info.manifest_digest, missing.manifest);
            for layer in &info.layers {
                let bytes = std::fs::read(&layer.path).unwrap();
                let hex: String = sha2::Sha256::digest(&bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert_eq!(format!("sha256:{hex}"), layer.digest);
            }
            assert!(
                content_store
                    .images_get(&record_name(&missing.manifest))
                    .await
                    .unwrap()
                    .is_none(),
                "temporary image record left behind"
            );
        });
    }

    #[test]
    fn docker_auth_splits_on_the_first_colon() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pa:ss");
        assert_eq!(
            decode_docker_auth(&encoded),
            Some(("user".to_string(), "pa:ss".to_string()))
        );
        assert_eq!(decode_docker_auth("not base64!"), None);
    }
}
