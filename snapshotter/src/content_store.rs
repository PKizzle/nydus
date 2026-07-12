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
//! Cross-runtime note: the snapshotter's main loop is a compio
//! `current_thread` runtime (so it can share an io-uring driver with
//! FUSE/fanotify) but tonic's transport requires a tokio runtime. We isolate
//! that with a dedicated multi-thread tokio runtime owned by this module and
//! drive each public async method via `blocking::unblock` → `handle.block_on`. The
//! compio scheduler keeps progressing while the gRPC call happens off-thread.

use crate::config::ContainerdConfig;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tonic::Code;
use tonic::metadata::MetadataValue;
use tracing::{debug, instrument};

/// Generated containerd protos. Module nesting must match the protobuf
/// package paths (`containerd.types`, `containerd.services.content.v1`,
/// `containerd.services.images.v1`) so the cross-package `super::…` refs
/// the prost generator emits (e.g. `Image.target:
/// super::super::super::types::Descriptor`) resolve.
mod containerd {
    pub mod types {
        tonic::include_proto!("containerd.types");
    }
    pub mod services {
        pub mod content {
            pub mod v1 {
                tonic::include_proto!("containerd.services.content.v1");
            }
        }
        pub mod images {
            pub mod v1 {
                tonic::include_proto!("containerd.services.images.v1");
            }
        }
    }
}

use containerd::services::content::v1::{
    InfoRequest, ListContentRequest, ReadContentRequest, UpdateRequest, WriteAction,
    WriteContentRequest, content_client::ContentClient,
};

use containerd::services::images::v1::{
    CreateImageRequest, GetImageRequest, Image, ListImagesRequest, UpdateImageRequest,
    images_client::ImagesClient,
};

use containerd::types as types_proto;

/// A snapshot of one content-store blob's metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentInfo {
    pub digest: String,
    pub size: u64,
    pub labels: HashMap<String, String>,
}

/// Containerd content-store client. Thread-safe; cheap to clone (state is
/// behind an `Arc`).
#[derive(Clone, Debug)]
pub struct ContentStoreClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    socket: PathBuf,
    namespace: String,
    content_root: PathBuf,
    /// `Option<Runtime>` rather than `Runtime` because `Runtime::drop`
    /// panics with "Cannot drop a runtime in a context where blocking is
    /// not allowed" when the drop happens on a tokio worker thread —
    /// which is exactly what would happen if the last
    /// `Arc<Inner>` outlived a future and got dropped from inside a
    /// `blocking::unblock` closure during shutdown. `Drop` for `Inner`
    /// pulls the runtime out via `.take()` and uses
    /// `shutdown_background()` to avoid the foot-gun entirely.
    rt: Option<tokio::runtime::Runtime>,
    /// Cloned `Handle` to the same runtime, used for all `block_on` calls on
    /// the hot path. Safety invariant: every `block_on` call site reaches
    /// this handle through a cloned `Arc<Inner>` that is moved into the
    /// `blocking::unblock` closure, so `Drop for Inner` — and therefore
    /// `shutdown_background()` — strictly happens-after the last in-flight
    /// `block_on` returns. Do not hand this `Handle` out detached from the
    /// `Arc<Inner>`: a `block_on` racing runtime shutdown would panic.
    handle: tokio::runtime::Handle,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl ContentStoreClient {
    /// Construct a client from configuration. Spawns the dedicated tokio
    /// runtime used for the gRPC transport.
    pub fn new(config: &ContainerdConfig) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("nydus-containerd-client")
            .build()
            .context("failed to build containerd gRPC client runtime")?;
        let handle = rt.handle().clone();
        Ok(Self {
            inner: Arc::new(Inner {
                socket: config.address(),
                namespace: config.namespace.clone(),
                content_root: config.content_root(),
                rt: Some(rt),
                handle,
            }),
        })
    }

    /// Resolve a digest to its on-disk path in the content store. Used by the
    /// fanotify backend dir to symlink to already-committed gzip-layer blobs
    /// without re-copying them. The well-known layout is stable across
    /// containerd 1.x and 2.x.
    pub fn blob_path(&self, digest: &str) -> PathBuf {
        let hex = strip_sha256_prefix(digest);
        self.inner
            .content_root
            .join("blobs")
            .join("sha256")
            .join(hex)
    }

    /// Probe whether a digest exists in the content store. Returns `None` for
    /// genuinely-absent blobs; bubbles up any other RPC error.
    #[instrument(level = "debug", skip(self), err)]
    pub async fn info(&self, digest: &str) -> Result<Option<ContentInfo>> {
        let inner = self.inner.clone();
        let digest = digest.to_string();
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect(&inner).await?;
                let mut request = tonic::Request::new(InfoRequest {
                    digest: digest.clone(),
                });
                attach_namespace(&mut request, &inner.namespace)?;
                match client.info(request).await {
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
            })
        })
        .await
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
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read {} for upload", path.display()))?;
        let digest = sha256_of_bytes(&bytes);
        let digest_with_prefix = format!("sha256:{digest}");

        if self.info(&digest_with_prefix).await?.is_some() {
            debug!(
                digest = %digest_with_prefix,
                "blob already present in content store; only applying labels"
            );
            self.apply_labels(&digest_with_prefix, &labels).await?;
            return Ok(digest_with_prefix);
        }

        let ref_hint = format!("nydus-auto-accel-{digest}");
        let inner = self.inner.clone();
        let digest_clone = digest_with_prefix.clone();
        let labels_clone = labels.clone();
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect(&inner).await?;
                let total = bytes.len() as i64;
                // Single-shot commit message. containerd accepts the whole
                // payload + commit in one frame as long as the data fits in
                // the gRPC max-message-size (64 MiB cap below).
                let req = WriteContentRequest {
                    action: WriteAction::Commit as i32,
                    r#ref: ref_hint,
                    total,
                    expected: digest_clone.clone(),
                    offset: 0,
                    data: bytes,
                    labels: labels_clone,
                };
                let stream = futures::stream::once(async move { req });
                let mut request = tonic::Request::new(stream);
                attach_namespace(&mut request, &inner.namespace)?;
                // Larger artifacts (merged bootstraps for multi-layer images)
                // can exceed tonic's default 4 MiB frame size.
                client = client.max_encoding_message_size(64 * 1024 * 1024);
                let mut response_stream = client
                    .write(request)
                    .await
                    .map_err(|status| anyhow::anyhow!("containerd Write failed: {status}"))?
                    .into_inner();
                while response_stream
                    .message()
                    .await
                    .map_err(|status| {
                        anyhow::anyhow!("containerd Write response failed: {status}")
                    })?
                    .is_some()
                {}
                Ok::<_, anyhow::Error>(())
            })
        })
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

        let inner = self.inner.clone();
        let digest_clone = digest_with_prefix.clone();
        let labels_clone = labels.clone();
        let data_owned = data.to_vec();
        let ref_owned = format!("nydus-auto-accel-{ref_hint}-{digest}");
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect(&inner).await?;
                let total = data_owned.len() as i64;
                let req = WriteContentRequest {
                    action: WriteAction::Commit as i32,
                    r#ref: ref_owned,
                    total,
                    expected: digest_clone.clone(),
                    offset: 0,
                    data: data_owned,
                    labels: labels_clone,
                };
                let stream = futures::stream::once(async move { req });
                let mut request = tonic::Request::new(stream);
                attach_namespace(&mut request, &inner.namespace)?;
                let mut response_stream = client
                    .write(request)
                    .await
                    .map_err(|status| anyhow::anyhow!("containerd Write failed: {status}"))?
                    .into_inner();
                while response_stream
                    .message()
                    .await
                    .map_err(|status| {
                        anyhow::anyhow!("containerd Write response failed: {status}")
                    })?
                    .is_some()
                {}
                Ok::<_, anyhow::Error>(())
            })
        })
        .await?;
        Ok(digest_with_prefix)
    }

    /// Apply / overwrite labels on a content blob. Idempotent.
    #[instrument(level = "debug", skip(self, labels), err)]
    async fn apply_labels(&self, digest: &str, labels: &HashMap<String, String>) -> Result<()> {
        if labels.is_empty() {
            return Ok(());
        }
        let inner = self.inner.clone();
        let digest = digest.to_string();
        let labels = labels.clone();
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect(&inner).await?;
                let info = containerd::services::content::v1::Info {
                    digest: digest.clone(),
                    labels,
                    ..Default::default()
                };
                let mut request = tonic::Request::new(UpdateRequest {
                    info: Some(info),
                    // FieldMask=labels: only labels are mutable in any case,
                    // but setting it explicitly is forward-compatible.
                    update_mask: Some(prost_types::FieldMask {
                        paths: vec!["labels".to_string()],
                    }),
                });
                attach_namespace(&mut request, &inner.namespace)?;
                client.update(request).await.map_err(|status| {
                    anyhow::anyhow!("containerd Update({digest}) failed: {status}")
                })?;
                Ok::<_, anyhow::Error>(())
            })
        })
        .await
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
        let inner = self.inner.clone();
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect(&inner).await?;
                let mut request = tonic::Request::new(ListContentRequest { filters });
                attach_namespace(&mut request, &inner.namespace)?;
                let mut stream = client
                    .list(request)
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
            })
        })
        .await
    }

    /// Fetch a content blob's bytes (used by sidecar discovery to read the
    /// auto-accel manifest JSON). Goes through the Read RPC so we don't
    /// depend on on-disk layout for arbitrary content; for large gzip-layer
    /// blobs use `blob_path()` + a streaming reader instead.
    #[instrument(level = "debug", skip(self), err)]
    pub async fn fetch_bytes(&self, digest: &str) -> Result<Vec<u8>> {
        let inner = self.inner.clone();
        let digest_owned = digest.to_string();
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect(&inner).await?;
                let mut request = tonic::Request::new(ReadContentRequest {
                    digest: digest_owned.clone(),
                    offset: 0,
                    size: 0,
                });
                attach_namespace(&mut request, &inner.namespace)?;
                let mut response = client
                    .read(request)
                    .await
                    .map_err(|status| {
                        anyhow::anyhow!("containerd Read({digest_owned}) failed: {status}")
                    })?
                    .into_inner();
                let mut out = Vec::new();
                while let Some(chunk) = response.message().await.map_err(|status| {
                    anyhow::anyhow!("containerd Read({digest_owned}) stream failed: {status}")
                })? {
                    out.extend_from_slice(&chunk.data);
                }
                Ok(out)
            })
        })
        .await
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
        let inner = self.inner.clone();
        let name = name.to_string();
        let digest = digest.to_string();
        let media_type = media_type.to_string();
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect_images(&inner).await?;
                let mut request = tonic::Request::new(CreateImageRequest {
                    image: Some(Image {
                        name: name.clone(),
                        labels,
                        target: Some(types_proto::Descriptor {
                            media_type,
                            digest,
                            size: size as i64,
                            annotations: HashMap::new(),
                        }),
                        created_at: None,
                        updated_at: None,
                    }),
                    source_date_epoch: None,
                });
                attach_namespace(&mut request, &inner.namespace)?;
                match client.create(request).await {
                    Ok(_) => Ok(()),
                    Err(status) if status.code() == Code::AlreadyExists => Ok(()),
                    Err(status) => Err(anyhow::anyhow!(
                        "containerd Images.Create({name}) failed: {status}"
                    )),
                }
            })
        })
        .await
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
        let inner = self.inner.clone();
        let name = name.to_string();
        let digest = digest.to_string();
        let media_type = media_type.to_string();
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect_images(&inner).await?;
                let image = Image {
                    name: name.clone(),
                    labels: labels.clone(),
                    target: Some(types_proto::Descriptor {
                        media_type: media_type.clone(),
                        digest: digest.clone(),
                        size: size as i64,
                        annotations: HashMap::new(),
                    }),
                    created_at: None,
                    updated_at: None,
                };
                let mut create = tonic::Request::new(CreateImageRequest {
                    image: Some(image.clone()),
                    source_date_epoch: None,
                });
                attach_namespace(&mut create, &inner.namespace)?;
                match client.create(create).await {
                    Ok(_) => Ok(()),
                    Err(status) if status.code() == Code::AlreadyExists => {
                        let mut update = tonic::Request::new(UpdateImageRequest {
                            image: Some(image),
                            update_mask: Some(prost_types::FieldMask {
                                paths: vec!["target".to_string(), "labels".to_string()],
                            }),
                            source_date_epoch: None,
                        });
                        attach_namespace(&mut update, &inner.namespace)?;
                        client.update(update).await.map(|_| ()).map_err(|status| {
                            anyhow::anyhow!("containerd Images.Update({name}) failed: {status}")
                        })
                    }
                    Err(status) => Err(anyhow::anyhow!(
                        "containerd Images.Create({name}) failed: {status}"
                    )),
                }
            })
        })
        .await
    }

    /// Look up a containerd Image record by name. Returns `None` for genuine
    /// NotFound; bubbles up any other RPC error. Used by sidecar discovery
    /// as a fast-path on top of (and before) the label-filter scan.
    #[instrument(level = "debug", skip(self), err)]
    pub async fn images_get(&self, name: &str) -> Result<Option<ContentInfo>> {
        let inner = self.inner.clone();
        let name = name.to_string();
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect_images(&inner).await?;
                let mut request = tonic::Request::new(GetImageRequest { name: name.clone() });
                attach_namespace(&mut request, &inner.namespace)?;
                match client.get(request).await {
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
            })
        })
        .await
    }

    /// List all containerd Image records (name + target digest). Used by
    /// `containerd_lookup` to build the chainID → image-ref cache without
    /// shelling out to `crictl images`.
    #[instrument(level = "debug", skip(self), err)]
    pub async fn images_list(&self) -> Result<Vec<crate::containerd_lookup::ImageRecord>> {
        let inner = self.inner.clone();
        blocking::unblock(move || {
            inner.handle.block_on(async {
                let mut client = connect_images(&inner).await?;
                let mut request = tonic::Request::new(ListImagesRequest { filters: vec![] });
                attach_namespace(&mut request, &inner.namespace)?;
                let response = client
                    .list(request)
                    .await
                    .map_err(|status| anyhow::anyhow!("containerd Images.List failed: {status}"))?;
                let records = response
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
                    .collect();
                Ok(records)
            })
        })
        .await
    }
}

/// Open a fresh Content service client over the configured Unix socket. The
/// tonic transport pins this future to the current tokio runtime, so it must
/// only be called inside `handle.block_on`.
async fn connect(inner: &Inner) -> Result<ContentClient<tonic::transport::Channel>> {
    Ok(ContentClient::new(connect_channel(inner).await?))
}

async fn connect_images(inner: &Inner) -> Result<ImagesClient<tonic::transport::Channel>> {
    Ok(ImagesClient::new(connect_channel(inner).await?))
}

async fn connect_channel(inner: &Inner) -> Result<tonic::transport::Channel> {
    let socket = inner.socket.clone();
    // The URI is a placeholder; the actual connection is established by the
    // service_fn connector which dials the Unix socket.
    tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_uri: tonic::transport::Uri| {
            let socket = socket.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&socket).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .with_context(|| {
            format!(
                "failed to connect to containerd at {}",
                inner.socket.display()
            )
        })
}

/// Attach the `containerd-namespace` metadata header that every containerd
/// gRPC request requires.
fn attach_namespace<T>(request: &mut tonic::Request<T>, namespace: &str) -> Result<()> {
    let value: MetadataValue<_> = namespace
        .parse()
        .with_context(|| format!("invalid containerd namespace {namespace:?}"))?;
    request.metadata_mut().insert("containerd-namespace", value);
    Ok(())
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
