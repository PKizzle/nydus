// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Containerd content store integration over the native Content gRPC API.
//!
//! The auto-accel pipeline needs to (a) READ the original gzip-layer blobs out
//! of containerd's content store as input to `local_accel::convert`, and (b)
//! UPLOAD the resulting sidecar artifacts (merged bootstrap, per-layer zran
//! indexes, optional prefetch blob, auto-accel manifest JSON) so spegel can
//! mirror them to peer nodes by content digest.
//!
//! Read access for large blobs (gzip layers, bootstraps used by the fanotify
//! backend dir) is purely on-disk via the well-known content-store layout
//! `<content_root>/blobs/sha256/<hex>` — stable across containerd 1.x and 2.x.
//! Metadata (Info, Update for labels) and small-blob upload/fetch go over the
//! Content gRPC service generated from the vendored protos under
//! `snapshotter/proto/`.
//!
//! Containerd's gRPC server requires a `containerd-namespace` metadata header
//! on every request; for k3s the namespace is `k8s.io`.
//!
//! Transport: the gRPC clients run on [`ContainerdChannel`] (`containerd_grpc.rs`), an HTTP/2
//! connection driven by the snapshotter's compio runtime. The channel also sets the
//! `containerd-namespace` header, so no method here handles it.

use crate::config::ContainerdConfig;
use crate::containerd_grpc::ContainerdChannel;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tonic::Code;
use tracing::{debug, error, instrument};

use crate::containerd_api::services::content::v1::{
    InfoRequest, ListContentRequest, ReadContentRequest, UpdateRequest, WriteAction,
    WriteContentRequest, content_client::ContentClient,
};

use crate::containerd_api::services::images::v1::{
    CreateImageRequest, DeleteImageRequest, GetImageRequest, Image, ListImagesRequest,
    UpdateImageRequest, images_client::ImagesClient,
};

use crate::containerd_api::types as types_proto;

/// A snapshot of one content-store blob's metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentInfo {
    pub digest: String,
    pub size: u64,
    pub labels: HashMap<String, String>,
}

/// Containerd content-store client. Cheap to clone; every clone shares the calling thread's
/// connection to containerd (see [`ContainerdChannel`]).
#[derive(Clone, Debug)]
pub struct ContentStoreClient {
    channel: ContainerdChannel,
    content_root: Arc<Path>,
}

impl ContentStoreClient {
    /// Construct a client from configuration. Connects lazily on the first call.
    pub fn new(config: &ContainerdConfig) -> Result<Self> {
        Ok(Self {
            channel: ContainerdChannel::new(config.address(), &config.namespace),
            content_root: Arc::from(config.content_root().as_path()),
        })
    }

    fn content(&self) -> ContentClient<ContainerdChannel> {
        ContentClient::new(self.channel.clone())
    }

    fn images(&self) -> ImagesClient<ContainerdChannel> {
        ImagesClient::new(self.channel.clone())
    }

    /// Resolve a digest to its on-disk path in the content store. Used by the
    /// fanotify backend dir to symlink to already-committed gzip-layer blobs
    /// without re-copying them. The well-known layout is stable across
    /// containerd 1.x and 2.x.
    pub fn blob_path(&self, digest: &str) -> PathBuf {
        let hex = strip_sha256_prefix(digest);
        self.content_root.join("blobs").join("sha256").join(hex)
    }

    /// Probe whether a digest exists in the content store. Returns `None` for
    /// genuinely-absent blobs; bubbles up any other RPC error.
    #[instrument(level = "debug", skip(self), err)]
    pub async fn info(&self, digest: &str) -> Result<Option<ContentInfo>> {
        let request = tonic::Request::new(InfoRequest {
            digest: digest.to_string(),
        });
        match self.content().info(request).await {
            Ok(response) => {
                let info = response
                    .into_inner()
                    .info
                    .context("containerd InfoResponse missing info field")?;
                Ok(Some(ContentInfo {
                    digest: info.digest,
                    size: info.size as u64,
                    labels: info.labels,
                }))
            }
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(anyhow::anyhow!(
                "containerd Info({digest}) failed: {status}"
            )),
        }
    }

    /// Upload a local file as a content blob, applying labels for GC + auto-accel
    /// discovery. Idempotent: if the digest already exists, we just (re-)apply
    /// labels via `Update`. Returns the canonical `sha256:...` digest.
    ///
    /// The Write RPC is bidirectional streaming; for our use case (a single
    /// already-on-disk file) we open the stream, send one `WriteContentRequest`
    /// with `action=Commit` + the full bytes + the expected digest + labels,
    /// and drain the response stream.
    #[instrument(level = "debug", skip(self, labels), fields(path = %path.display()), err)]
    pub async fn write_blob(&self, path: &Path, labels: HashMap<String, String>) -> Result<String> {
        // Read + hash off the compio reactor: merged bootstraps scale with the
        // image's file count, and a multi-MiB synchronous read would stall the
        // event loop for its duration.
        let path_buf = path.to_path_buf();
        let (bytes, digest) = blocking::unblock(move || {
            let bytes = std::fs::read(&path_buf)
                .with_context(|| format!("failed to read {} for upload", path_buf.display()))?;
            let digest = sha256_of_bytes(&bytes);
            Ok::<_, anyhow::Error>((bytes, digest))
        })
        .await?;
        let digest_with_prefix = format!("sha256:{digest}");

        if self.info(&digest_with_prefix).await?.is_some() {
            debug!(
                digest = %digest_with_prefix,
                "blob already present in content store; only applying labels"
            );
            self.apply_labels(&digest_with_prefix, &labels).await?;
            return Ok(digest_with_prefix);
        }

        // Larger artifacts (merged bootstraps for multi-layer images) can exceed
        // tonic's default 4 MiB frame size.
        self.commit(
            format!("nydus-auto-accel-{digest}"),
            &digest_with_prefix,
            bytes,
            labels,
        )
        .await?;
        Ok(digest_with_prefix)
    }

    /// Write an in-memory byte slice as a content blob. Used for the small
    /// auto-accel manifest JSON.
    pub async fn write_bytes(
        &self,
        data: &[u8],
        ref_hint: &str,
        labels: HashMap<String, String>,
    ) -> Result<String> {
        let digest = sha256_of_bytes(data);
        let digest_with_prefix = format!("sha256:{digest}");

        if self.info(&digest_with_prefix).await?.is_some() {
            self.apply_labels(&digest_with_prefix, &labels).await?;
            return Ok(digest_with_prefix);
        }

        // Peers route bootstrap-sized blobs through this path too, so it gets
        // write_blob's raised frame cap instead of relying on the payload
        // staying small.
        self.commit(
            format!("nydus-auto-accel-{ref_hint}-{digest}"),
            &digest_with_prefix,
            data.to_vec(),
            labels,
        )
        .await?;
        Ok(digest_with_prefix)
    }

    /// Single-shot `Write`: one frame carrying the whole payload, the expected
    /// digest, the labels and `action=Commit`, then drain the response stream.
    /// containerd accepts that as long as the payload fits the 64 MiB frame cap.
    async fn commit(
        &self,
        ref_name: String,
        expected: &str,
        data: Vec<u8>,
        labels: HashMap<String, String>,
    ) -> Result<()> {
        let request = WriteContentRequest {
            action: WriteAction::Commit as i32,
            r#ref: ref_name,
            total: data.len() as i64,
            expected: expected.to_string(),
            offset: 0,
            data,
            labels,
        };
        let mut client = self.content().max_encoding_message_size(64 * 1024 * 1024);
        let mut responses = client
            .write(tonic::Request::new(futures::stream::once(async move {
                request
            })))
            .await
            .map_err(|status| anyhow::anyhow!("containerd Write failed: {status}"))?
            .into_inner();
        while responses
            .message()
            .await
            .map_err(|status| anyhow::anyhow!("containerd Write response failed: {status}"))?
            .is_some()
        {}
        Ok(())
    }

    /// Apply / overwrite labels on a content blob. Idempotent.
    #[instrument(level = "debug", skip(self, labels), err)]
    async fn apply_labels(&self, digest: &str, labels: &HashMap<String, String>) -> Result<()> {
        if labels.is_empty() {
            return Ok(());
        }
        let info = crate::containerd_api::services::content::v1::Info {
            digest: digest.to_string(),
            labels: labels.clone(),
            ..Default::default()
        };
        let request = tonic::Request::new(UpdateRequest {
            info: Some(info),
            // FieldMask=labels: only labels are mutable in any case,
            // but setting it explicitly is forward-compatible.
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["labels".to_string()],
            }),
        });
        self.content()
            .update(request)
            .await
            .map_err(|status| anyhow::anyhow!("containerd Update({digest}) failed: {status}"))?;
        Ok(())
    }

    /// List content blobs matching the given containerd-style filters.
    /// Filters use containerd's filter syntax, e.g.
    /// `labels."containerd.io/gc.ref.content.subject"==sha256:abc`. Returns
    /// the matched blobs' info (digest, size, labels) in arbitrary order.
    ///
    /// Used by sidecar discovery: to find the auto-accel manifest blob for
    /// an image whose digest we know, we filter by
    /// `gc.ref.content.subject == <manifest>` AND
    /// `nydus.auto-accel.role == manifest`.
    #[instrument(level = "debug", skip(self), err)]
    pub async fn list_with_filters(&self, filters: Vec<String>) -> Result<Vec<ContentInfo>> {
        let mut stream = self
            .content()
            .list(tonic::Request::new(ListContentRequest { filters }))
            .await
            .map_err(|status| anyhow::anyhow!("containerd List failed: {status}"))?
            .into_inner();
        let mut out = Vec::new();
        while let Some(chunk) = stream
            .message()
            .await
            .map_err(|status| anyhow::anyhow!("containerd List stream failed: {status}"))?
        {
            for info in chunk.info {
                out.push(ContentInfo {
                    digest: info.digest,
                    size: info.size as u64,
                    labels: info.labels,
                });
            }
        }
        Ok(out)
    }

    /// Fetch a content blob's bytes (used by sidecar discovery to read the
    /// auto-accel manifest JSON). Goes through the Read RPC so we don't
    /// depend on on-disk layout for arbitrary content; for large gzip-layer
    /// blobs use `blob_path()` + a streaming reader instead.
    ///
    /// A digest absent from the store is not necessarily a fault: a
    /// host-matching index child that was never pulled, or a sidecar blob
    /// containerd garbage-collected (see `completeness_check` in
    /// auto_zran.rs). NotFound is therefore logged at debug and left to the
    /// caller, which knows whether the digest was speculative; every other
    /// failure is logged here at error, and callers do not log it again
    /// (`is_rpc_failure`). Read RPC errors keep their `tonic::Status` in
    /// the chain so `is_not_found` can classify them.
    #[instrument(level = "debug", skip(self))]
    pub async fn fetch_bytes(&self, digest: &str) -> Result<Vec<u8>> {
        let result = self.read_bytes(digest).await;
        if let Err(e) = &result {
            if is_not_found(e) {
                debug!(error = %e, "containerd content read failed");
            } else {
                error!(error = %e, "containerd content read failed");
            }
        }
        result
    }

    async fn read_bytes(&self, digest: &str) -> Result<Vec<u8>> {
        let request = tonic::Request::new(ReadContentRequest {
            digest: digest.to_string(),
            offset: 0,
            size: 0,
        });
        let mut response = self
            .content()
            .read(request)
            .await
            .map_err(|status| read_error(digest, "failed", status))?
            .into_inner();
        let mut out = Vec::new();
        while let Some(chunk) = response
            .message()
            .await
            .map_err(|status| read_error(digest, "stream failed", status))?
        {
            out.extend_from_slice(&chunk.data);
        }
        Ok(out)
    }

    /// Register a containerd Image record pointing at an existing content
    /// blob (typically an auto-accel manifest just uploaded via
    /// `write_blob`). Idempotent: if an image with the same name already
    /// exists, we treat the AlreadyExists status as success — last-write
    /// semantics are the caller's concern (auto_zran picks
    /// "largest-size manifest wins" elsewhere).
    ///
    /// The image record is what k3s's embedded spegel advertises to peers;
    /// without it the manifest sits in the content store but spegel has no
    /// name to publish.
    #[instrument(level = "debug", skip(self, labels), err)]
    pub async fn images_create(
        &self,
        name: &str,
        digest: &str,
        size: u64,
        media_type: &str,
        labels: HashMap<String, String>,
    ) -> Result<()> {
        let request = tonic::Request::new(CreateImageRequest {
            image: Some(image_record(name, digest, size, media_type, labels)),
            source_date_epoch: None,
        });
        match self.images().create(request).await {
            Ok(_) => Ok(()),
            Err(status) if status.code() == Code::AlreadyExists => Ok(()),
            Err(status) => Err(anyhow::anyhow!(
                "containerd Images.Create({name}) failed: {status}"
            )),
        }
    }

    /// Create the sidecar Image record, or—if it already exists—repoint it at
    /// `digest` (with fresh `labels`). Containerd's `Images.Create` returns
    /// `AlreadyExists` and does NOT update the target, so the two-stage
    /// auto-accel pipeline needs this upsert to promote a base sidecar record
    /// to the optimized manifest on stage 2. The `Update` uses a field mask of
    /// `target` + `labels` so timestamps and other server-managed fields are
    /// left untouched. Idempotent: a create/update to the same target is a
    /// no-op from the caller's perspective.
    pub async fn images_upsert(
        &self,
        name: &str,
        digest: &str,
        size: u64,
        media_type: &str,
        labels: HashMap<String, String>,
    ) -> Result<()> {
        let image = image_record(name, digest, size, media_type, labels);
        let mut client = self.images();
        let create = tonic::Request::new(CreateImageRequest {
            image: Some(image.clone()),
            source_date_epoch: None,
        });
        match client.create(create).await {
            Ok(_) => Ok(()),
            Err(status) if status.code() == Code::AlreadyExists => {
                let update = tonic::Request::new(UpdateImageRequest {
                    image: Some(image),
                    update_mask: Some(prost_types::FieldMask {
                        paths: vec!["target".to_string(), "labels".to_string()],
                    }),
                    source_date_epoch: None,
                });
                client.update(update).await.map(|_| ()).map_err(|status| {
                    anyhow::anyhow!("containerd Images.Update({name}) failed: {status}")
                })
            }
            Err(status) => Err(anyhow::anyhow!(
                "containerd Images.Create({name}) failed: {status}"
            )),
        }
    }

    /// Look up a containerd Image record by name. Returns `None` for genuine
    /// NotFound; bubbles up any other RPC error. Used by sidecar discovery
    /// as a fast-path on top of (and before) the label-filter scan.
    #[instrument(level = "debug", skip(self), err)]
    pub async fn images_get(&self, name: &str) -> Result<Option<ContentInfo>> {
        let request = tonic::Request::new(GetImageRequest {
            name: name.to_string(),
        });
        match self.images().get(request).await {
            Ok(response) => {
                let Some(image) = response.into_inner().image else {
                    return Ok(None);
                };
                let Some(target) = image.target else {
                    return Ok(None);
                };
                Ok(Some(ContentInfo {
                    digest: target.digest,
                    size: target.size as u64,
                    labels: image.labels,
                }))
            }
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(anyhow::anyhow!(
                "containerd Images.Get({name}) failed: {status}"
            )),
        }
    }

    /// List all containerd Image records (name + target digest). Used by
    /// `containerd_lookup` to build the chainID → image-ref cache without
    /// shelling out to `crictl images`.
    #[instrument(level = "debug", skip(self), err)]
    pub async fn images_list(&self) -> Result<Vec<crate::containerd_lookup::ImageRecord>> {
        let response = self
            .images()
            .list(tonic::Request::new(ListImagesRequest { filters: vec![] }))
            .await
            .map_err(|status| anyhow::anyhow!("containerd Images.List failed: {status}"))?;
        Ok(response
            .into_inner()
            .images
            .into_iter()
            .filter_map(|image| {
                let target = image.target?;
                Some(crate::containerd_lookup::ImageRecord {
                    name: image.name,
                    target_digest: target.digest,
                })
            })
            .collect())
    }

    /// Delete a containerd Image record by name. Idempotent: NotFound is
    /// success. Used by the reconciler's sidecar sweep — dropping the record
    /// un-roots the sidecar blob tree so containerd's (asynchronous) GC can
    /// collect it, which in turn releases the original gzip layers the
    /// sidecar's `gc.ref.content.*` labels were keeping alive.
    #[instrument(level = "debug", skip(self), err)]
    pub async fn images_delete(&self, name: &str) -> Result<()> {
        let request = tonic::Request::new(DeleteImageRequest {
            name: name.to_string(),
            sync: false,
        });
        match self.images().delete(request).await {
            Ok(_) => Ok(()),
            Err(status) if status.code() == Code::NotFound => Ok(()),
            Err(status) => Err(anyhow::anyhow!(
                "containerd Images.Delete({name}) failed: {status}"
            )),
        }
    }
}

/// An Image record named `name` whose target is the given descriptor.
fn image_record(
    name: &str,
    digest: &str,
    size: u64,
    media_type: &str,
    labels: HashMap<String, String>,
) -> Image {
    Image {
        name: name.to_string(),
        labels,
        target: Some(types_proto::Descriptor {
            media_type: media_type.to_string(),
            digest: digest.to_string(),
            size: size as i64,
            annotations: HashMap::new(),
        }),
        created_at: None,
        updated_at: None,
    }
}

/// A Read RPC error that keeps the `tonic::Status` downcastable under its
/// message, so `is_not_found`/`is_rpc_failure` see the code.
fn read_error(digest: &str, what: &str, status: tonic::Status) -> anyhow::Error {
    let msg = format!("containerd Read({digest}) {what}: {status}");
    anyhow::Error::new(status).context(msg)
}

/// The content-store read of this error's digest answered NotFound.
pub(crate) fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<tonic::Status>()
        .is_some_and(|s| s.code() == Code::NotFound)
}

/// A gRPC failure other than NotFound, which `fetch_bytes` has already
/// logged at error; callers that log fetch failures skip these.
pub(crate) fn is_rpc_failure(e: &anyhow::Error) -> bool {
    e.downcast_ref::<tonic::Status>()
        .is_some_and(|s| s.code() != Code::NotFound)
}

fn sha256_of_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Hash a file with a streaming reader so we don't load it into memory.
/// Kept for future direct-streaming uploads of multi-GiB layers; current
/// `write_blob` reads the whole file (the artifacts we upload are small
/// merged bootstraps + KB-scale zran indexes).
#[allow(dead_code)]
fn sha256_of_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn strip_sha256_prefix(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_path_strips_sha256_prefix() {
        let cfg = ContainerdConfig {
            content_root: Some(PathBuf::from(
                "/var/lib/containerd/io.containerd.content.v1.content",
            )),
            ..Default::default()
        };
        let client = ContentStoreClient::new(&cfg).unwrap();
        assert_eq!(
            client.blob_path("sha256:abc123"),
            PathBuf::from(
                "/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/abc123"
            )
        );
        assert_eq!(
            client.blob_path("abc123"),
            PathBuf::from(
                "/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/abc123"
            )
        );
    }

    /// NotFound stays recognisable under the context `read_bytes` and
    /// `walk_manifest_via_grpc` attach (`fetch_bytes` attaches none); other
    /// codes and non-gRPC errors do not match.
    #[test]
    fn is_not_found_sees_status_through_context() {
        let wrap = |status: tonic::Status| {
            anyhow::Error::new(status)
                .context("containerd Read(sha256:x) failed")
                .context("fetch manifest sha256:x")
        };
        assert!(is_not_found(&wrap(tonic::Status::not_found("gone"))));
        assert!(!is_not_found(&wrap(tonic::Status::unavailable("down"))));
        assert!(!is_not_found(&anyhow::anyhow!("connect failed")));
    }

    /// The error `read_bytes` builds is the one `fetch_bytes` classifies:
    /// if it stops carrying the `tonic::Status`, every NotFound is logged
    /// at error again.
    #[test]
    fn read_error_keeps_status_downcastable() {
        let e = read_error("sha256:x", "failed", tonic::Status::not_found("gone"));
        assert!(is_not_found(&e));
        assert!(!is_rpc_failure(&e));
        assert!(e.to_string().contains("containerd Read(sha256:x)"), "{e}");
        let e = read_error(
            "sha256:x",
            "stream failed",
            tonic::Status::unavailable("down"),
        );
        assert!(!is_not_found(&e));
        assert!(is_rpc_failure(&e));
        assert!(!is_rpc_failure(&anyhow::anyhow!("connect failed")));
    }

    #[test]
    fn sha256_of_bytes_matches_known_vector() {
        // `printf 'hello\n' | sha256sum`
        assert_eq!(
            sha256_of_bytes(b"hello\n"),
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }

    #[test]
    fn sha256_of_file_matches_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"hello\n").unwrap();
        assert_eq!(
            sha256_of_file(&path).unwrap(),
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }
}
