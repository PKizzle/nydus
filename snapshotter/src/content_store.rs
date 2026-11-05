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
use crate::containerd_grpc::{ContainerdChannel, ContainerdFault, containerd_fault};
use anyhow::{Context, Result};
use futures::{Stream, StreamExt};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tonic::Code;
use tracing::{debug, error, instrument, warn};

use crate::containerd_api::services::content::v1::{
    InfoRequest, ListContentRequest, ReadContentRequest, UpdateRequest, WriteAction,
    WriteContentRequest, WriteContentResponse, content_client::ContentClient,
};

use crate::containerd_api::services::images::v1::{
    CreateImageRequest, DeleteImageRequest, GetImageRequest, Image, ListImagesRequest,
    UpdateImageRequest, images_client::ImagesClient,
};

use crate::containerd_api::services::leases::v1::{
    AddResourceRequest, CreateRequest as LeaseCreateRequest, DeleteRequest as LeaseDeleteRequest,
    Resource as LeaseResource, leases_client::LeasesClient,
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

    fn leases(&self) -> LeasesClient<ContainerdChannel> {
        LeasesClient::new(self.channel.clone())
    }

    /// The containerd socket this client talks to.
    pub fn socket(&self) -> &Path {
        self.channel.socket()
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
            Err(status) => Err(rpc_error(format_args!("Info({digest})"), status)),
        }
    }

    /// Create a lease that keeps the content written under it from containerd's GC, and return
    /// its id. containerd collects committed content nothing references, and an upload's blobs
    /// are only referenced once the Image record that roots them exists; the lease covers that
    /// gap. [`Upload::finish_upsert`] / [`Upload::finish_create`] delete it once the record
    /// exists. A lease left behind by a failed upload expires after [`UPLOAD_LEASE_TTL`]
    /// (`containerd.io/gc.expire`), long enough for a retry to find the blobs still there.
    async fn create_lease(&self, purpose: &str) -> Result<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let expire = prost_types::Timestamp {
            seconds: (now + UPLOAD_LEASE_TTL).as_secs() as i64,
            nanos: 0,
        };
        let id = format!("nydus-{purpose}-{}", now.as_nanos());
        self.leases()
            .create(LeaseCreateRequest {
                id: id.clone(),
                labels: HashMap::from([(
                    "containerd.io/gc.expire".to_string(),
                    expire.to_string(),
                )]),
            })
            .await
            .map_err(|status| rpc_error(format_args!("Leases.Create({id})"), status))?;
        Ok(id)
    }

    /// Start an upload: every blob written through the returned [`Upload`] goes under one new
    /// lease, which its `finish_*` method deletes once an Image record roots them.
    pub async fn begin_upload(&self, purpose: &str) -> Result<Upload> {
        Ok(Upload {
            lease: self.create_lease(purpose).await?,
            client: self.clone(),
        })
    }

    /// Delete a lease. Idempotent: an already expired lease is success.
    async fn delete_lease(&self, id: &str) -> Result<()> {
        let request = LeaseDeleteRequest {
            id: id.to_string(),
            sync: false,
        };
        match self.leases().delete(request).await {
            Ok(_) => Ok(()),
            Err(status) if status.code() == Code::NotFound => Ok(()),
            Err(status) => Err(rpc_error(format_args!("Leases.Delete({id})"), status)),
        }
    }

    /// Upload a local file as a content blob under `lease`, applying labels for GC + auto-accel
    /// discovery. Idempotent: if the digest already exists, it is added to the lease and its
    /// labels are (re-)applied. Returns the canonical `sha256:...` digest.
    ///
    /// The file is hashed in one pass, then streamed over the bidirectional Write RPC in
    /// [`WRITE_CHUNK_SIZE`] reads (see [`write_requests`]), so it is never held in memory whole.
    /// Both passes run off the compio reactor.
    #[instrument(level = "debug", skip(self, labels), fields(path = %path.display()), err)]
    async fn write_blob(
        &self,
        path: &Path,
        labels: HashMap<String, String>,
        lease: &str,
    ) -> Result<String> {
        let path = path.to_path_buf();
        let hash_path = path.clone();
        let (digest, total) = blocking::unblock(move || sha256_of_file(&hash_path))
            .await
            .with_context(|| format!("failed to hash {} for upload", path.display()))?;
        let digest_with_prefix = format!("sha256:{digest}");
        self.store(
            lease,
            format!("nydus-auto-accel-{digest}"),
            &digest_with_prefix,
            total,
            labels,
            file_chunks(path, total),
        )
        .await?;
        Ok(digest_with_prefix)
    }

    /// Write an in-memory byte slice as a content blob under `lease`. Used for the small
    /// auto-accel manifest JSON. Idempotent like [`Self::write_blob`].
    async fn write_bytes(
        &self,
        data: &[u8],
        ref_hint: &str,
        labels: HashMap<String, String>,
        lease: &str,
    ) -> Result<String> {
        let digest = sha256_of_bytes(data);
        let digest_with_prefix = format!("sha256:{digest}");
        // Peers route bootstrap-sized blobs through this path too.
        self.store(
            lease,
            format!("nydus-auto-accel-{ref_hint}-{digest}"),
            &digest_with_prefix,
            data.len() as u64,
            labels,
            futures::stream::iter(memory_chunks(data).map(Ok)),
        )
        .await?;
        Ok(digest_with_prefix)
    }

    /// Store `total` bytes from `chunks` as blob `expected` under `lease`, unless it is already
    /// present, in which case it is only adopted (see [`Self::adopt`]).
    async fn store<S>(
        &self,
        lease: &str,
        ref_name: String,
        expected: &str,
        total: u64,
        labels: HashMap<String, String>,
        chunks: S,
    ) -> Result<()>
    where
        S: Stream<Item = io::Result<Vec<u8>>> + Send + 'static,
    {
        if self.info(expected).await?.is_some() {
            debug!(
                digest = %expected,
                "blob already present in content store; only adding it to the lease and applying labels"
            );
            return self.adopt(lease, expected, &labels).await;
        }
        let committed = self
            .commit(lease, ref_name, expected, total, labels.clone(), chunks)
            .await;
        settle_commit(
            committed,
            async || Ok(self.info(expected).await?.is_some()),
            async || self.adopt(lease, expected, &labels).await,
        )
        .await
    }

    /// Stream `chunks` to containerd as a chunked `Write` session ending in a commit, under
    /// `lease`. A chunk that fails to read ends the session and is reported as the error.
    async fn commit<S>(
        &self,
        lease: &str,
        ref_name: String,
        expected: &str,
        total: u64,
        labels: HashMap<String, String>,
        chunks: S,
    ) -> Result<()>
    where
        S: Stream<Item = io::Result<Vec<u8>>> + Send + 'static,
    {
        let read_failure = Arc::new(Mutex::new(None::<io::Error>));
        let slot = read_failure.clone();
        let chunks = chunks.scan((), move |_, chunk| {
            futures::future::ready(match chunk {
                Ok(data) => Some(data),
                Err(e) => {
                    if let Ok(mut slot) = slot.lock() {
                        *slot = Some(e);
                    }
                    None
                }
            })
        });
        let mut request =
            tonic::Request::new(write_requests(ref_name, expected, total, labels, chunks));
        request.metadata_mut().insert(
            "containerd-lease",
            lease
                .parse()
                .context("lease id is not a valid header value")?,
        );
        let written =
            async {
                let mut responses = self
                    .content()
                    .write(request)
                    .await
                    .map_err(|status| rpc_error(format_args!("Write({expected})"), status))?
                    .into_inner();
                let mut last = None;
                while let Some(response) = responses.message().await.map_err(|status| {
                    rpc_error(format_args!("Write({expected}) response"), status)
                })? {
                    last = Some(response);
                }
                check_committed(last, expected, total)
            }
            .await;
        if let Some(e) = read_failure.lock().ok().and_then(|mut slot| slot.take()) {
            return Err(anyhow::Error::new(e).context(format!("read payload of {expected}")));
        }
        written
    }

    /// Take an already-present blob into `lease` and (re-)apply its labels. The blob may be
    /// unreferenced (left by an earlier, failed upload), so without the lease containerd's GC
    /// could collect it before the Image record that roots it exists.
    async fn adopt(
        &self,
        lease: &str,
        digest: &str,
        labels: &HashMap<String, String>,
    ) -> Result<()> {
        self.leases()
            .add_resource(AddResourceRequest {
                id: lease.to_string(),
                resource: Some(LeaseResource {
                    id: digest.to_string(),
                    r#type: "content".to_string(),
                }),
            })
            .await
            .map_err(|status| {
                rpc_error(
                    format_args!("Leases.AddResource({lease}, {digest})"),
                    status,
                )
            })?;
        self.apply_labels(digest, labels).await
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
            .map_err(|status| rpc_error(format_args!("Update({digest})"), status))?;
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
            .map_err(|status| rpc_error("List", status))?
            .into_inner();
        let mut out = Vec::new();
        while let Some(chunk) = stream
            .message()
            .await
            .map_err(|status| rpc_error("List stream", status))?
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
            .map_err(|status| rpc_error(format_args!("Read({digest})"), status))?
            .into_inner();
        let mut out = Vec::new();
        while let Some(chunk) = response
            .message()
            .await
            .map_err(|status| rpc_error(format_args!("Read({digest}) stream"), status))?
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
        self.create_image(name, digest, size, media_type, labels)
            .await
            .map(drop)
    }

    /// [`Self::images_create`], returning whether it created the record (`false`: one by that
    /// name already existed and was left as it is).
    async fn create_image(
        &self,
        name: &str,
        digest: &str,
        size: u64,
        media_type: &str,
        labels: HashMap<String, String>,
    ) -> Result<bool> {
        let request = tonic::Request::new(CreateImageRequest {
            image: Some(image_record(name, digest, size, media_type, labels)),
            source_date_epoch: None,
        });
        match self.images().create(request).await {
            Ok(_) => Ok(true),
            Err(status) if status.code() == Code::AlreadyExists => Ok(false),
            Err(status) => Err(rpc_error(format_args!("Images.Create({name})"), status)),
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
                client
                    .update(update)
                    .await
                    .map(|_| ())
                    .map_err(|status| rpc_error(format_args!("Images.Update({name})"), status))
            }
            Err(status) => Err(rpc_error(format_args!("Images.Create({name})"), status)),
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
            Err(status) => Err(rpc_error(format_args!("Images.Get({name})"), status)),
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
            .map_err(|status| rpc_error("Images.List", status))?;
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
            Err(status) => Err(rpc_error(format_args!("Images.Delete({name})"), status)),
        }
    }
}

/// One upload: blobs written under a single containerd lease that keeps them from GC until an
/// Image record roots them. Finishing creates that record and deletes the lease; an upload
/// dropped without finishing leaves its lease to expire ([`UPLOAD_LEASE_TTL`]), so a retry
/// still finds the blobs.
#[derive(Debug)]
#[must_use = "an upload's lease is deleted only by finishing it"]
pub struct Upload {
    client: ContentStoreClient,
    lease: String,
}

impl Upload {
    /// The id of this upload's lease.
    pub fn lease(&self) -> &str {
        &self.lease
    }

    /// See [`ContentStoreClient::write_blob`].
    pub async fn write_blob(&self, path: &Path, labels: HashMap<String, String>) -> Result<String> {
        self.client.write_blob(path, labels, &self.lease).await
    }

    /// See [`ContentStoreClient::write_bytes`].
    pub async fn write_bytes(
        &self,
        data: &[u8],
        ref_hint: &str,
        labels: HashMap<String, String>,
    ) -> Result<String> {
        self.client
            .write_bytes(data, ref_hint, labels, &self.lease)
            .await
    }

    /// Point Image record `name` at `digest`, creating or overwriting it
    /// ([`ContentStoreClient::images_upsert`]), then delete the lease.
    pub async fn finish_upsert(
        self,
        name: &str,
        digest: &str,
        size: u64,
        media_type: &str,
        labels: HashMap<String, String>,
    ) -> Result<()> {
        self.client
            .images_upsert(name, digest, size, media_type, labels)
            .await?;
        self.release().await;
        Ok(())
    }

    /// Create Image record `name` for `digest` unless one exists
    /// ([`ContentStoreClient::images_create`]), and delete the lease only once the record
    /// verifiably points at `digest`: it created the record, or the one that already existed
    /// reads back with that target. A record pointing elsewhere does not root these blobs, so
    /// the lease stays until it expires and this is an error.
    pub async fn finish_create(
        self,
        name: &str,
        digest: &str,
        size: u64,
        media_type: &str,
        labels: HashMap<String, String>,
    ) -> Result<()> {
        let created = self
            .client
            .create_image(name, digest, size, media_type, labels)
            .await?;
        if created {
            self.release().await;
            return Ok(());
        }
        match self.client.images_get(name).await? {
            Some(record) if record.digest == digest => {
                self.release().await;
                Ok(())
            }
            other => Err(anyhow::anyhow!(
                "image record {name} points at {}, not {digest}; lease {} keeps the upload until \
                 it expires",
                other.map_or_else(|| "nothing".to_string(), |record| record.digest),
                self.lease
            )),
        }
    }

    /// Delete the lease. One that cannot be deleted only lingers until it expires, so that is
    /// logged, not returned.
    async fn release(self) {
        if let Err(e) = self.client.delete_lease(&self.lease).await {
            warn!(lease = %self.lease, error = %format!("{e:#}"), "could not delete an upload lease; it expires on its own");
        }
    }
}

/// Lifetime of an upload lease that is never deleted because its upload failed: long enough
/// for the retries of the failed job to reuse its blobs, short enough that superseded blobs do
/// not linger. A successful upload deletes its lease as soon as the Image record roots the blobs.
pub const UPLOAD_LEASE_TTL: std::time::Duration = std::time::Duration::from_secs(2 * 60 * 60);

/// Payload bytes per `WriteContentRequest`, as containerd's own client sends.
/// containerd's gRPC server rejects any message over 16 MiB.
const WRITE_CHUNK_SIZE: usize = 1024 * 1024;

/// containerd ends a `Write` session whose request stream closes before the
/// commit without an error, so only a final commit response for the whole
/// payload proves the blob was stored.
fn check_committed(last: Option<WriteContentResponse>, expected: &str, total: u64) -> Result<()> {
    match last {
        Some(r)
            if r.action == WriteAction::Commit as i32
                && r.digest == expected
                && r.offset == total as i64 =>
        {
            Ok(())
        }
        other => Err(anyhow::anyhow!(
            "containerd Write of {expected} ended without committing it (last response: {other:?})"
        )),
    }
}

/// The outcome of a `Write` session. `AlreadyExists` means another writer committed the same
/// digest first; like containerd's own client, that counts as stored once `exists` confirms
/// the blob is there, and the blob is then `adopt`ed (lease + labels) as a present one is.
async fn settle_commit(
    committed: Result<()>,
    exists: impl AsyncFnOnce() -> Result<bool>,
    adopt: impl AsyncFnOnce() -> Result<()>,
) -> Result<()> {
    match committed {
        Err(e) if status_code(&e) == Some(Code::AlreadyExists) => {
            if !exists().await? {
                return Err(
                    e.context("containerd reported the blob as existing, but Info cannot find it")
                );
            }
            adopt().await
        }
        other => other,
    }
}

/// The messages of one content `Write` session for a `total`-byte payload read as `chunks`:
/// `Write` actions at their running offsets, the chunk that completes the payload sent as
/// `Commit` with the labels. The first message names the ref, size and digest (containerd
/// opens the writer from it) and, at offset 0, truncates whatever an earlier aborted session
/// left under the same ref. The digest goes only on the first message and the commit, as in
/// containerd's own client: containerd looks it up in its metadata store for every message
/// that carries one, so repeating it on each data message costs one lookup per chunk. A source that ends early ends the session without a commit, which
/// [`check_committed`] reports.
fn write_requests<C: Stream<Item = Vec<u8>>>(
    mut ref_name: String,
    expected: &str,
    total: u64,
    mut labels: HashMap<String, String>,
    chunks: C,
) -> impl Stream<Item = WriteContentRequest> + use<C> {
    let expected = expected.to_string();
    let mut offset = 0u64;
    chunks.map(move |data| {
        let start = offset;
        offset += data.len() as u64;
        let last = offset >= total;
        WriteContentRequest {
            action: if last {
                WriteAction::Commit
            } else {
                WriteAction::Write
            } as i32,
            r#ref: std::mem::take(&mut ref_name),
            total: total as i64,
            expected: if start == 0 || last {
                expected.clone()
            } else {
                String::new()
            },
            offset: start as i64,
            data,
            labels: if last {
                std::mem::take(&mut labels)
            } else {
                HashMap::new()
            },
        }
    })
}

/// `data` in [`WRITE_CHUNK_SIZE`] pieces; one empty piece for an empty payload, so that it is
/// still committed.
fn memory_chunks(data: &[u8]) -> impl Iterator<Item = Vec<u8>> + Send + 'static {
    let pieces: Vec<Vec<u8>> = if data.is_empty() {
        vec![Vec::new()]
    } else {
        data.chunks(WRITE_CHUNK_SIZE).map(<[u8]>::to_vec).collect()
    };
    pieces.into_iter()
}

/// The first `total` bytes of the file at `path` in [`WRITE_CHUNK_SIZE`] reads, each run off the
/// compio reactor. The file is opened on the first poll. A file shorter than `total` yields an
/// `UnexpectedEof` error, after which the stream ends.
fn file_chunks(
    path: PathBuf,
    total: u64,
) -> impl Stream<Item = io::Result<Vec<u8>>> + Send + 'static {
    // State: the open file (after the first read), the next offset, whether a chunk was sent.
    futures::stream::unfold(Some((None::<std::fs::File>, 0u64, false)), move |state| {
        let path = path.clone();
        async move {
            let (file, offset, started) = state?;
            if started && offset >= total {
                return None;
            }
            let len = (total - offset).min(WRITE_CHUNK_SIZE as u64);
            let read = blocking::unblock(move || {
                let mut file = match file {
                    Some(file) => file,
                    None => std::fs::File::open(&path)?,
                };
                let mut buf = Vec::with_capacity(len as usize);
                (&mut file).take(len).read_to_end(&mut buf)?;
                if (buf.len() as u64) < len {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                Ok((file, buf))
            })
            .await;
            Some(match read {
                Ok((file, buf)) => (Ok(buf), Some((Some(file), offset + len, true))),
                Err(e) => (Err(e), None),
            })
        }
    })
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

/// A failed containerd call, its `tonic::Status` kept downcastable under the message so
/// [`is_not_found`] and [`is_rpc_failure`] see the code, and with it any transport error
/// tonic keeps as its source, which [`containerd_fault_of`] classifies.
pub(crate) fn rpc_error(call: impl std::fmt::Display, status: tonic::Status) -> anyhow::Error {
    let msg = format!("containerd {call} failed: {status}");
    anyhow::Error::new(status).context(msg)
}

fn status_code(e: &anyhow::Error) -> Option<Code> {
    e.downcast_ref::<tonic::Status>().map(tonic::Status::code)
}

/// The content-store read of this error's digest answered NotFound.
pub(crate) fn is_not_found(e: &anyhow::Error) -> bool {
    status_code(e) == Some(Code::NotFound)
}

/// A gRPC failure other than NotFound. For `fetch_bytes` errors, which it has already logged
/// at error; callers that log fetch failures skip these.
pub(crate) fn is_rpc_failure(e: &anyhow::Error) -> bool {
    status_code(e).is_some_and(|code| code != Code::NotFound)
}

/// What `e` says about containerd itself (see [`containerd_fault`]); `None` when containerd
/// answered, whatever the gRPC status, or the error is local.
pub fn containerd_fault_of(e: &anyhow::Error) -> Option<ContainerdFault> {
    containerd_fault(e.as_ref())
}

/// Whether `e` is containerd being unreachable for now ([`ContainerdFault::Unreachable`]): no
/// answer, so nothing about the request, and worth retrying once containerd is back.
pub fn is_containerd_unavailable(e: &anyhow::Error) -> bool {
    containerd_fault_of(e) == Some(ContainerdFault::Unreachable)
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

/// The sha256 hex digest and size of the file at `path`, read in one streaming pass.
fn sha256_of_file(path: &Path) -> io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hex_encode(&hasher.finalize()), size))
}

fn strip_sha256_prefix(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containerd_grpc::ChannelError;

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

    /// The error every containerd call builds is the one callers classify: if it stops carrying
    /// the `tonic::Status`, NotFound is logged at error again and an outage counts as a failure.
    #[test]
    fn rpc_error_keeps_status_downcastable() {
        let e = rpc_error("Read(sha256:x)", tonic::Status::not_found("gone"));
        assert!(is_not_found(&e));
        assert!(!is_rpc_failure(&e));
        assert!(e.to_string().contains("containerd Read(sha256:x)"), "{e}");
        let e = rpc_error("Images.Get(x)", tonic::Status::unavailable("down"));
        assert!(!is_not_found(&e));
        assert!(is_rpc_failure(&e));
        assert!(!is_rpc_failure(&anyhow::anyhow!("connect failed")));
    }

    /// Unreachable means the request never got an answer: a socket that is missing in its
    /// directory or refuses connections. A status containerd sent is an answer about the
    /// request, whatever its code; a socket path that cannot work is misconfiguration; a local
    /// error is neither.
    #[test]
    fn containerd_unavailable_is_told_apart_from_real_failures() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("containerd.sock");
        let channel = |socket: &Path, errno: i32| {
            let status = tonic::Status::from_error(Box::new(ChannelError::Connect {
                socket: socket.to_path_buf(),
                source: io::Error::from_raw_os_error(errno),
            }));
            anyhow::Error::new(status).context("containerd Write(sha256:x) failed")
        };
        assert!(is_containerd_unavailable(&channel(&socket, libc::ENOENT)));
        assert!(is_containerd_unavailable(&channel(
            &socket,
            libc::ECONNREFUSED
        )));

        let misconfigured = channel(&socket, libc::EACCES);
        assert!(!is_containerd_unavailable(&misconfigured));
        assert_eq!(
            containerd_fault_of(&misconfigured),
            Some(ContainerdFault::Misconfigured(socket.clone()))
        );

        let status = |status: tonic::Status| rpc_error("Transfer", status);
        for answered in [
            tonic::Status::deadline_exceeded("registry fetch timed out"),
            tonic::Status::unavailable("ref locked"),
            tonic::Status::not_found("gone"),
            tonic::Status::already_exists("present"),
        ] {
            let e = status(answered);
            assert_eq!(containerd_fault_of(&e), None, "{e:#}");
        }
        assert!(!is_containerd_unavailable(&anyhow::Error::new(
            io::Error::from(io::ErrorKind::ConnectionReset)
        )));
        assert!(!is_containerd_unavailable(&anyhow::anyhow!(
            "convert failed"
        )));
    }

    /// The classification holds through tonic's real error path, not only for hand-built
    /// errors: a call to a socket missing from an existing directory reads as an outage, one
    /// whose directory is missing as misconfiguration. Fails if tonic stops keeping the
    /// transport error as the status's source.
    #[test]
    fn a_real_call_to_a_missing_socket_is_classified_through_tonic() {
        let dir = tempfile::tempdir().unwrap();
        let call = |socket: PathBuf| {
            let client = ContentStoreClient::new(&ContainerdConfig {
                address: Some(socket),
                ..Default::default()
            })
            .unwrap();
            compio::runtime::Runtime::new()
                .unwrap()
                .block_on(client.info(&format!("sha256:{}", "0".repeat(64))))
                .unwrap_err()
        };
        let e = call(dir.path().join("containerd.sock"));
        assert!(is_containerd_unavailable(&e), "{e:#}");
        let socket = dir.path().join("missing/containerd.sock");
        let e = call(socket.clone());
        assert_eq!(
            containerd_fault_of(&e),
            Some(ContainerdFault::Misconfigured(socket)),
            "{e:#}"
        );
    }

    fn collect_requests(
        total: u64,
        chunks: impl Stream<Item = Vec<u8>>,
        labels: HashMap<String, String>,
    ) -> Vec<WriteContentRequest> {
        futures::executor::block_on(
            write_requests("ref".into(), "sha256:x", total, labels, chunks).collect(),
        )
    }

    /// Asserts `reqs` is one well-formed session for `data`: messages under containerd's
    /// 16 MiB limit at contiguous offsets, ref only on the first, one commit at the end that
    /// carries `labels`.
    fn assert_session(reqs: &[WriteContentRequest], data: &[u8], labels: &HashMap<String, String>) {
        let mut joined = Vec::new();
        for (i, req) in reqs.iter().enumerate() {
            assert!(prost::Message::encoded_len(req) < 16 * 1024 * 1024);
            assert!(req.data.len() <= WRITE_CHUNK_SIZE);
            assert_eq!(req.offset as usize, joined.len());
            assert_eq!(req.total as usize, data.len());
            let carries_digest = i == 0 || i + 1 == reqs.len();
            assert_eq!(req.expected, if carries_digest { "sha256:x" } else { "" });
            assert_eq!(req.r#ref, if i == 0 { "ref" } else { "" });
            let last = i + 1 == reqs.len();
            let action = if last {
                WriteAction::Commit
            } else {
                WriteAction::Write
            };
            assert_eq!(req.action, action as i32);
            assert_eq!(req.labels.is_empty(), !last || labels.is_empty());
            joined.extend_from_slice(&req.data);
        }
        assert_eq!(joined, data);
        assert_eq!(&reqs.last().unwrap().labels, labels);
    }

    /// A payload over containerd's 16 MiB receive limit goes out as messages that each stay
    /// under it.
    #[test]
    fn write_requests_split_large_payload() {
        let data: Vec<u8> = (0..33 * 1024 * 1024 + 7).map(|i| i as u8).collect();
        let labels = HashMap::from([("k".to_string(), "v".to_string())]);
        let reqs = collect_requests(
            data.len() as u64,
            futures::stream::iter(memory_chunks(&data)),
            labels.clone(),
        );
        assert_eq!(reqs.len(), 34);
        assert_session(&reqs, &data, &labels);
    }

    /// A file streams as the same session its bytes would, one `WRITE_CHUNK_SIZE` read at a
    /// time, without being read into memory first.
    #[test]
    fn file_chunks_stream_a_file_as_one_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let data: Vec<u8> = (0..3 * WRITE_CHUNK_SIZE + 5)
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&path, &data).unwrap();
        let labels = HashMap::from([("k".to_string(), "v".to_string())]);
        let chunks = file_chunks(path, data.len() as u64).map(Result::unwrap);
        let reqs = collect_requests(data.len() as u64, chunks, labels.clone());
        assert_eq!(reqs.len(), 4);
        assert_session(&reqs, &data, &labels);
    }

    /// An empty file is still committed, in a single message.
    #[test]
    fn file_chunks_commit_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty");
        std::fs::write(&path, b"").unwrap();
        let chunks = file_chunks(path, 0).map(Result::unwrap);
        let reqs = collect_requests(0, chunks, HashMap::new());
        assert_eq!(reqs.len(), 1);
        assert_session(&reqs, &[], &HashMap::new());
    }

    /// A file that shrank after it was hashed yields a raw `UnexpectedEof` and ends the stream,
    /// so the session cannot commit a short payload.
    #[test]
    fn file_chunks_report_a_file_shorter_than_its_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, vec![7u8; WRITE_CHUNK_SIZE + 10]).unwrap();
        let items: Vec<_> = futures::executor::block_on(
            file_chunks(path.clone(), (2 * WRITE_CHUNK_SIZE) as u64).collect(),
        );
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_ref().unwrap().len(), WRITE_CHUNK_SIZE);
        assert_eq!(
            items[1].as_ref().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let missing: Vec<_> =
            futures::executor::block_on(file_chunks(dir.path().join("absent"), 1).collect());
        assert_eq!(missing.len(), 1);
        assert_eq!(
            missing[0].as_ref().unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    /// Only a commit response covering the whole payload counts as stored.
    #[test]
    fn check_committed_requires_a_full_commit_response() {
        let ok = |action: WriteAction, digest: &str, offset: i64| {
            let response = WriteContentResponse {
                action: action as i32,
                digest: digest.to_string(),
                offset,
                ..Default::default()
            };
            check_committed(Some(response), "sha256:x", 5).is_ok()
        };
        assert!(ok(WriteAction::Commit, "sha256:x", 5));
        // Request stream closed after a Write: containerd answers with that Write's status.
        assert!(!ok(WriteAction::Write, "sha256:x", 5));
        assert!(!ok(WriteAction::Commit, "sha256:y", 5));
        assert!(!ok(WriteAction::Commit, "sha256:x", 4));
        assert!(check_committed(None, "sha256:x", 5).is_err());
    }

    /// An empty payload is still committed, in a single message.
    #[test]
    fn write_requests_empty_payload_commits() {
        let reqs = collect_requests(0, futures::stream::iter(memory_chunks(&[])), HashMap::new());
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].action, WriteAction::Commit as i32);
        assert_eq!(reqs[0].r#ref, "ref");
    }

    /// `AlreadyExists` from a commit is success once Info confirms the blob, which is then
    /// adopted; it is an error if Info cannot find it. Other outcomes pass through untouched.
    #[test]
    fn settle_commit_treats_already_exists_as_stored() {
        let exists = tonic::Status::already_exists("content sha256:x: already exists");
        let settle = |committed: Result<()>, present: bool| {
            let adopted = std::cell::Cell::new(false);
            let result = futures::executor::block_on(settle_commit(
                committed,
                async || Ok(present),
                async || {
                    adopted.set(true);
                    Ok(())
                },
            ));
            (result, adopted.get())
        };

        let (result, adopted) = settle(Err(rpc_error("Write(sha256:x)", exists.clone())), true);
        assert!(result.is_ok() && adopted);

        let (result, adopted) = settle(Err(rpc_error("Write(sha256:x)", exists)), false);
        assert!(!adopted);
        assert_eq!(status_code(&result.unwrap_err()), Some(Code::AlreadyExists));

        let (result, adopted) = settle(Ok(()), true);
        assert!(result.is_ok() && !adopted);

        let unavailable = rpc_error("Write(sha256:x)", tonic::Status::unavailable("down"));
        let (result, adopted) = settle(Err(unavailable), true);
        assert!(!adopted && status_code(&result.unwrap_err()) == Some(Code::Unavailable));
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
            (
                "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".to_string(),
                6
            )
        );
    }
}
