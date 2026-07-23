// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! The OCI Distribution client: manifest/blob pull and push against a single
//! registry.
//!
//! Every operation goes through the same auth pipeline (see [`crate::auth`]):
//! send with the best credential at hand, and on `401` parse that response's
//! `WWW-Authenticate` challenge, fetch a bearer token (scoped `pull` for reads
//! and `pull,push` for uploads), cache it, and retry exactly once.
//!
//! Push uses the spec's **monolithic** upload: `POST /v2/<repo>/blobs/uploads/`
//! opens a session, and one `PUT <Location>?digest=sha256:...` uploads the
//! whole blob (`Location` may be absolute or relative and may already carry
//! query parameters — see [`resolve_location`] / [`append_query_param`]).
//! Blob pushes are deduplicated with a `HEAD` probe first. Chunked `PATCH`
//! uploads are out of scope for now.
//!
//! Public operations return the typed [`RegistryError`] (see [`crate::error`])
//! so callers can branch on `NotFound` / `ReferrersUnsupported` / auth /
//! digest / timeout failures; internal helpers stay on `anyhow` and flow
//! through the transparent `Other` catch-all.

use crate::auth::{
    BearerChallenge, Credentials, TokenCache, auth_header_value, docker_config_auth,
    fetch_bearer_token, mount_scope, parse_bearer_challenge, percent_encode_query, pull_scope,
    push_scope,
};
use crate::error::RegistryError;
use crate::types::{
    Index, MANIFEST_ACCEPT, MEDIA_TYPE_OCI_INDEX, MEDIA_TYPE_OCTET_STREAM, sha256_digest,
};
use anyhow::{Context, Result, anyhow, bail};
use compio::BufResult;
use compio::io::{AsyncReadAt, AsyncWriteAtExt};
use cyper::{Client, Response};
use futures::StreamExt;
use http::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue, LOCATION,
    WWW_AUTHENTICATE,
};
use http::{Method, StatusCode};
use sha2::{Digest as _, Sha256};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, warn};

/// Upper bound on a registry body buffered into memory by [`RegistryClient::
/// get_manifest`] / [`RegistryClient::get_blob`]. Exists so a hostile or
/// misbehaving registry cannot OOM the caller; 512 MiB is deliberately
/// generous (a merged nydus bootstrap stays well under it). File downloads
/// ([`RegistryClient::get_blob_to_file`]) stream to disk and are not capped.
const MAX_REGISTRY_BODY_BYTES: u64 = 512 * 1024 * 1024;

/// Chunk size for hashing local files before upload.
const FILE_HASH_CHUNK: usize = 1024 * 1024;

/// Upper bound on the response-body snippet captured into
/// [`RegistryError::Http`] for diagnosis. Registries put small structured
/// error JSON there; anything larger is truncated noise.
const MAX_ERROR_BODY_BYTES: u64 = 4 * 1024;

/// Per-call disambiguator for [`RegistryClient::get_blob_to_file`]'s temp
/// file name, on top of the process id. The pid alone only makes the name
/// unique per *process*: two concurrent `get_blob_to_file` calls in the same
/// process targeting the same destination path would otherwise share one
/// `part.<pid>` temp file and race on `File::create`'s truncation. The
/// counter is bumped on every call, making each call's temp path unique
/// regardless of in-process concurrency.
static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Options for [`RegistryClient::new`].
#[derive(Clone, Debug)]
pub struct RegistryClientOptions {
    /// Use cleartext `http://` instead of `https://`.
    ///
    /// SECURITY: plain HTTP disables transport encryption AND server
    /// authentication; an on-path attacker can read and tamper with manifests
    /// and blobs. Only enable for registries on a trusted network.
    pub plain_http: bool,
    /// Accept invalid/self-signed TLS certificates
    /// (`danger_accept_invalid_certs`). Same MITM exposure caveat as
    /// [`plain_http`](Self::plain_http).
    pub insecure_tls: bool,
    /// Extra PEM CA root files trusted in addition to the platform store
    /// (for registries signed by a private CA). Ignored when
    /// [`insecure_tls`](Self::insecure_tls) is set — verification is off
    /// entirely then, so extra roots would be misleading.
    pub ca_cert_files: Vec<PathBuf>,
    /// Per-request timeout for metadata requests (manifest GET/PUT, HEAD,
    /// upload POST, token fetch) and for each streamed download chunk. cyper
    /// has no client-level timeout, so it is applied per request via
    /// `compio::time::timeout`. `None` disables it.
    pub timeout: Option<Duration>,
    /// Timeout for the blob-upload `PUT` (which transmits the entire body
    /// before resolving, so it must scale with blob size). Defaults to `None`
    /// (unbounded) because a fixed value would break large pushes on slow
    /// links.
    pub upload_timeout: Option<Duration>,
    /// Wall-clock deadline for reading a whole in-memory response body
    /// (manifests, [`RegistryClient::get_blob`]). The byte cap bounds size,
    /// not time — without this, a slow-drip response trickling in just fast
    /// enough to keep reads alive can hold the caller indefinitely. Generous
    /// default (5 minutes) so slow-but-honest links are unaffected; file
    /// downloads ([`RegistryClient::get_blob_to_file`]) are not covered (they
    /// scale with blob size and make observable progress on disk).
    pub body_timeout: Option<Duration>,
    /// Explicit credentials. Take precedence over docker `config.json`.
    pub credentials: Option<Credentials>,
    /// Explicit docker `config.json` path for credential loading. When
    /// `None`, the default location is used (`$DOCKER_CONFIG/config.json`,
    /// else `~/.docker/config.json`).
    pub docker_config: Option<PathBuf>,
    /// Whether to consult docker `config.json` at all when no explicit
    /// credentials are given.
    pub use_docker_config: bool,
}

impl Default for RegistryClientOptions {
    fn default() -> Self {
        Self {
            plain_http: false,
            insecure_tls: false,
            ca_cert_files: Vec::new(),
            timeout: Some(Duration::from_secs(30)),
            upload_timeout: None,
            body_timeout: Some(Duration::from_secs(300)),
            credentials: None,
            docker_config: None,
            use_docker_config: true,
        }
    }
}

/// A fetched manifest: raw bytes plus the digest and content type needed to
/// re-reference or re-push it.
#[derive(Clone, Debug)]
pub struct FetchedManifest {
    /// Raw manifest bytes exactly as served (hash-stable).
    pub bytes: Vec<u8>,
    /// sha256 digest of [`bytes`](Self::bytes), computed locally (the
    /// `Docker-Content-Digest` header is cross-checked but never trusted).
    pub digest: String,
    /// `Content-Type` of the response, when the registry sent one (this is
    /// the manifest's media type).
    pub content_type: Option<String>,
}

/// Request body for a single attempt. Rebuildable, so the 401-retry can
/// resend it (a streaming body cannot be replayed once consumed).
enum BodySource<'a> {
    /// No body.
    Empty,
    /// In-memory body; copied per attempt.
    Bytes(&'a [u8]),
    /// Streamed from a file (re-opened per attempt) with an explicit
    /// `Content-Length` header, as the distribution spec requires for
    /// monolithic uploads.
    File(&'a Path),
}

/// OCI Distribution client bound to one registry host.
///
/// `!Send` by design: it holds a [`cyper::Client`] (Rc-based, bound to the
/// compio current-thread runtime). Construct and use it on one thread.
pub struct RegistryClient {
    client: Client,
    /// `scheme://host[:port]`, no trailing slash.
    base: String,
    timeout: Option<Duration>,
    upload_timeout: Option<Duration>,
    body_timeout: Option<Duration>,
    /// base64 `user:password` payload (or full `Basic `/`Bearer ` value).
    basic_auth: Option<String>,
    tokens: RefCell<TokenCache>,
}

impl RegistryClient {
    /// Create a client for `registry` (an API host like `registry-1.docker.io`
    /// or `registry.local:5000` — use [`crate::ImageReference::api_host`] so
    /// `docker.io` is normalized).
    ///
    /// Credential resolution: `opts.credentials` wins; otherwise docker
    /// `config.json` is consulted (unless disabled); otherwise requests start
    /// anonymous and rely on the bearer-token flow.
    pub fn new(registry: &str, opts: RegistryClientOptions) -> Result<Self, RegistryError> {
        let scheme = if opts.plain_http { "http" } else { "https" };
        let builder = if opts.insecure_tls {
            Client::builder()
                .use_rustls_default()
                .danger_accept_invalid_certs(true)
        } else if !opts.ca_cert_files.is_empty() {
            Client::builder().use_rustls(crate::tls::client_config_with_extra_roots(
                &opts.ca_cert_files,
            )?)
        } else {
            Client::builder().use_rustls_default()
        };
        let client = builder
            .build()
            .context("failed to build registry HTTP client")?;
        let basic_auth = match opts.credentials.as_ref() {
            Some(creds) => Some(creds.to_base64()),
            None if opts.use_docker_config => {
                docker_config_auth(opts.docker_config.as_deref(), registry)
            }
            None => None,
        };
        Ok(Self {
            client,
            base: format!("{scheme}://{registry}"),
            timeout: opts.timeout,
            upload_timeout: opts.upload_timeout,
            body_timeout: opts.body_timeout,
            basic_auth,
            tokens: RefCell::new(TokenCache::new()),
        })
    }

    /// GET a manifest by tag or digest (`/v2/<repo>/manifests/<reference>`)
    /// with the full OCI/docker Accept list. When `reference` is a digest the
    /// body is verified against it; the returned digest is always computed
    /// locally from the bytes.
    pub async fn get_manifest(
        &self,
        repo: &str,
        reference: &str,
    ) -> Result<FetchedManifest, RegistryError> {
        let url = self.manifest_url(repo, reference);
        let response = self
            .request_with_auth(
                Method::GET,
                &url,
                &pull_scope(repo),
                &[(ACCEPT, HeaderValue::from_static(MANIFEST_ACCEPT))],
                BodySource::Empty,
                self.timeout,
            )
            .await?;
        if !response.status().is_success() {
            return Err(self
                .error_for_status(response, &format!("manifest {repo}:{reference}"), &url)
                .await);
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let header_digest = response
            .headers()
            .get("docker-content-digest")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let bytes =
            read_bounded(response, &url, MAX_REGISTRY_BODY_BYTES, self.body_timeout).await?;
        let digest = sha256_digest(&bytes);
        if reference.starts_with("sha256:") && !digest.eq_ignore_ascii_case(reference) {
            return Err(RegistryError::DigestMismatch {
                expected: reference.to_string(),
                actual: digest,
            });
        }
        if let Some(claimed) = header_digest
            && !claimed.eq_ignore_ascii_case(&digest)
        {
            warn!(%repo, %reference, %claimed, computed = %digest, "registry Docker-Content-Digest disagrees with computed digest; using computed");
        }
        Ok(FetchedManifest {
            bytes,
            digest,
            content_type,
        })
    }

    /// GET a blob (`/v2/<repo>/blobs/<digest>`) into memory. Bounded to
    /// [`MAX_REGISTRY_BODY_BYTES`] and digest-verified. For large blobs use
    /// [`get_blob_to_file`](Self::get_blob_to_file).
    pub async fn get_blob(&self, repo: &str, digest: &str) -> Result<Vec<u8>, RegistryError> {
        let url = self.blob_url(repo, digest);
        let response = self.get_blob_response(repo, digest).await?;
        let bytes =
            read_bounded(response, &url, MAX_REGISTRY_BODY_BYTES, self.body_timeout).await?;
        let computed = sha256_digest(&bytes);
        if !computed.eq_ignore_ascii_case(digest) {
            return Err(RegistryError::DigestMismatch {
                expected: digest.to_string(),
                actual: computed,
            });
        }
        Ok(bytes)
    }

    /// GET a blob and stream it to `path` (via an adjacent temp file renamed
    /// into place), verifying the sha256 digest as chunks arrive. Returns the
    /// number of bytes written. Not size-capped: the destination is disk.
    pub async fn get_blob_to_file(
        &self,
        repo: &str,
        digest: &str,
        path: &Path,
    ) -> Result<u64, RegistryError> {
        let response = self.get_blob_response(repo, digest).await?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create blob directory {}", parent.display()))?;
        }
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("part.{}.{seq}", std::process::id()));
        let mut file = compio::fs::File::create(&tmp)
            .await
            .with_context(|| format!("create blob temp file {}", tmp.display()))?;

        let mut hasher = Sha256::new();
        let mut written = 0u64;
        let mut stream = Box::pin(response.bytes_stream());
        let result: Result<(), RegistryError> = async {
            loop {
                let next = stream.next();
                let item = match self.timeout {
                    Some(duration) => {
                        compio::time::timeout(duration, next).await.map_err(|_| {
                            RegistryError::Timeout(format!("blob download for {digest} stalled"))
                        })?
                    }
                    None => next.await,
                };
                let Some(chunk) = item else { break };
                let chunk = chunk.with_context(|| format!("read blob chunk for {digest}"))?;
                hasher.update(&chunk);
                let len = chunk.len() as u64;
                let BufResult(write_result, _) = file.write_all_at(chunk, written).await;
                write_result.with_context(|| format!("write blob to {}", tmp.display()))?;
                written += len;
            }
            let computed = format!("sha256:{}", hex::encode(hasher.finalize()));
            if !computed.eq_ignore_ascii_case(digest) {
                return Err(RegistryError::DigestMismatch {
                    expected: digest.to_string(),
                    actual: computed,
                });
            }
            Ok(())
        }
        .await;
        drop(file);
        if let Err(e) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            // Don't leave the `.part` temp file behind on a failed rename.
            let _ = std::fs::remove_file(&tmp);
            return Err(RegistryError::Other(
                anyhow::Error::new(e)
                    .context(format!("rename blob into place at {}", path.display())),
            ));
        }
        Ok(written)
    }

    /// HEAD a blob (`/v2/<repo>/blobs/<digest>`): `true` when it exists,
    /// `false` on 404, error on anything else.
    pub async fn head_blob(&self, repo: &str, digest: &str) -> Result<bool, RegistryError> {
        let url = self.blob_url(repo, digest);
        let response = self
            .request_with_auth(
                Method::HEAD,
                &url,
                &pull_scope(repo),
                &[],
                BodySource::Empty,
                self.timeout,
            )
            .await?;
        match response.status() {
            status if status.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => Err(self
                .error_for_status(response, &format!("blob HEAD {digest}"), &url)
                .await),
        }
    }

    /// Try to cross-repo mount `digest` from `from_repo` into `repo`
    /// (`POST /v2/<repo>/blobs/uploads/?mount=<digest>&from=<from_repo>`).
    /// Returns `true` on `201 Created` (mounted). A `202 Accepted` means the
    /// registry declined the mount and opened a regular upload session
    /// instead; that session is cancelled best-effort and `false` is returned
    /// so the caller falls back to a normal push.
    pub async fn mount_blob(
        &self,
        repo: &str,
        digest: &str,
        from_repo: &str,
    ) -> Result<bool, RegistryError> {
        let url = append_query_param(
            &append_query_param(&self.upload_url(repo), "mount", digest),
            "from",
            from_repo,
        );
        let response = self
            .request_with_auth(
                Method::POST,
                &url,
                &mount_scope(repo, from_repo),
                &[],
                BodySource::Empty,
                self.timeout,
            )
            .await?;
        match response.status() {
            StatusCode::CREATED => Ok(true),
            StatusCode::ACCEPTED => {
                if let Some(location) = header_str(&response, &LOCATION) {
                    self.cancel_upload(repo, &location).await;
                }
                Ok(false)
            }
            _ => Err(self
                .error_for_status(
                    response,
                    &format!("blob mount of {digest} from {from_repo}"),
                    &url,
                )
                .await),
        }
    }

    /// Push in-memory bytes as a blob (HEAD-dedup, then monolithic upload).
    /// Returns the blob's `sha256:<hex>` digest.
    pub async fn push_blob_bytes(&self, repo: &str, bytes: &[u8]) -> Result<String, RegistryError> {
        let digest = sha256_digest(bytes);
        if self.blob_already_present(repo, &digest).await {
            return Ok(digest);
        }
        self.monolithic_upload(repo, &digest, BodySource::Bytes(bytes))
            .await?;
        Ok(digest)
    }

    /// Push a file as a blob: the sha256 is computed while streaming the file
    /// once, existing blobs are deduplicated via HEAD, and the upload streams
    /// the file with an explicit `Content-Length` (never buffering it whole).
    /// Returns the blob's `sha256:<hex>` digest.
    pub async fn push_blob_file(&self, repo: &str, path: &Path) -> Result<String, RegistryError> {
        let digest = self.file_digest(path).await?;
        if self.blob_already_present(repo, &digest).await {
            return Ok(digest);
        }
        self.monolithic_upload(repo, &digest, BodySource::File(path))
            .await?;
        Ok(digest)
    }

    /// PUT a manifest (`/v2/<repo>/manifests/<reference>`) with the given
    /// `Content-Type`. `reference` may be a tag or a digest. Returns the
    /// manifest's computed `sha256:<hex>` digest.
    pub async fn push_manifest(
        &self,
        repo: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<String, RegistryError> {
        let url = self.manifest_url(repo, reference);
        let content_type =
            HeaderValue::from_str(media_type).context("invalid manifest media type")?;
        let response = self
            .request_with_auth(
                Method::PUT,
                &url,
                &push_scope(repo),
                &[(CONTENT_TYPE, content_type)],
                BodySource::Bytes(bytes),
                self.timeout,
            )
            .await?;
        if !response.status().is_success() {
            return Err(self
                .error_for_status(response, &format!("manifest push {repo}:{reference}"), &url)
                .await);
        }
        Ok(sha256_digest(bytes))
    }

    /// GET the OCI 1.1 referrers list for `subject_digest`
    /// (`/v2/<repo>/referrers/<digest>`, OCI distribution spec 1.1). The
    /// response is an OCI image index whose `manifests[]` are the descriptors
    /// of the artifact manifests referring to the subject (each carrying the
    /// artifact's `artifactType` and `annotations`).
    ///
    /// `artifact_type`, when given, is sent as the spec's `artifactType`
    /// query filter AND re-applied client-side (via [`filter_referrers`]):
    /// the spec allows servers to ignore the query filter, so the local
    /// filter is authoritative.
    ///
    /// Returns [`RegistryError::ReferrersUnsupported`] when the registry does
    /// not support the referrers API (a `404` on the endpoint — also
    /// tolerating the `405`/`400`/`501` shapes seen from older registries),
    /// so callers can fall back to the `sha256-<subject-hex>` fallback tag.
    /// A registry that *does* support the API but has no referrers returns an
    /// empty index, per spec.
    pub async fn get_referrers(
        &self,
        repo: &str,
        subject_digest: &str,
        artifact_type: Option<&str>,
    ) -> Result<Index, RegistryError> {
        let mut url = self.referrers_url(repo, subject_digest);
        if let Some(filter) = artifact_type {
            url = append_query_param(&url, "artifactType", filter);
        }
        let response = self
            .request_with_auth(
                Method::GET,
                &url,
                &pull_scope(repo),
                &[(ACCEPT, HeaderValue::from_static(MEDIA_TYPE_OCI_INDEX))],
                BodySource::Empty,
                self.timeout,
            )
            .await?;
        match response.status() {
            status if status.is_success() => {}
            // 404 is the spec's "referrers API not supported" signal; 405/400/
            // 501 are equivalent shapes observed from pre-1.1 registries.
            StatusCode::NOT_FOUND
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::BAD_REQUEST
            | StatusCode::NOT_IMPLEMENTED => {
                debug!(%repo, subject = %subject_digest, status = %response.status(), "registry does not support the OCI referrers API");
                return Err(RegistryError::ReferrersUnsupported);
            }
            _ => {
                return Err(self
                    .error_for_status(response, &format!("referrers of {subject_digest}"), &url)
                    .await);
            }
        }
        let bytes =
            read_bounded(response, &url, MAX_REGISTRY_BODY_BYTES, self.body_timeout).await?;
        let mut index: Index = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse referrers index for {subject_digest}"))?;
        if let Some(filter) = artifact_type {
            filter_referrers(&mut index, filter);
        }
        Ok(index)
    }

    /// GET the blob endpoint and ensure a success status (shared by the
    /// in-memory and to-file downloads).
    async fn get_blob_response(&self, repo: &str, digest: &str) -> Result<Response, RegistryError> {
        let url = self.blob_url(repo, digest);
        let response = self
            .request_with_auth(
                Method::GET,
                &url,
                &pull_scope(repo),
                &[(ACCEPT, HeaderValue::from_static(MEDIA_TYPE_OCTET_STREAM))],
                BodySource::Empty,
                self.timeout,
            )
            .await?;
        if !response.status().is_success() {
            return Err(self
                .error_for_status(response, &format!("blob {digest}"), &url)
                .await);
        }
        Ok(response)
    }

    /// Map a non-success response to the typed error: `404` →
    /// [`RegistryError::NotFound`], `401`/`403` → [`RegistryError::Auth`]
    /// (the auth retry already ran inside [`Self::request_with_auth`]),
    /// anything else → [`RegistryError::Http`] with a bounded body snippet
    /// (registries put their structured error JSON there).
    async fn error_for_status(
        &self,
        response: Response,
        resource: &str,
        url: &str,
    ) -> RegistryError {
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return RegistryError::NotFound {
                resource: resource.to_string(),
            };
        }
        let body = read_bounded(response, url, MAX_ERROR_BODY_BYTES, self.body_timeout)
            .await
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
            .unwrap_or_default();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return RegistryError::Auth(format!("HTTP {status} for {resource}: {body}"));
        }
        RegistryError::Http {
            status: status.as_u16(),
            body,
            resource: resource.to_string(),
        }
    }

    /// HEAD-dedup probe for pushes. Probe failures are logged and treated as
    /// "absent" so a flaky HEAD never blocks an upload that might succeed.
    async fn blob_already_present(&self, repo: &str, digest: &str) -> bool {
        match self.head_blob(repo, digest).await {
            Ok(true) => {
                debug!(%repo, %digest, "blob already present; skipping upload");
                true
            }
            Ok(false) => false,
            Err(e) => {
                debug!(%repo, %digest, error = %e, "blob HEAD probe failed; attempting upload anyway");
                false
            }
        }
    }

    /// The spec's monolithic two-step upload: POST to open a session, PUT the
    /// whole body to the returned `Location` with `?digest=` appended.
    async fn monolithic_upload(
        &self,
        repo: &str,
        digest: &str,
        body: BodySource<'_>,
    ) -> Result<(), RegistryError> {
        let scope = push_scope(repo);
        let session_url = self.upload_url(repo);
        let response = self
            .request_with_auth(
                Method::POST,
                &session_url,
                &scope,
                &[],
                BodySource::Empty,
                self.timeout,
            )
            .await?;
        if !response.status().is_success() {
            return Err(self
                .error_for_status(
                    response,
                    &format!("blob upload session for {repo}"),
                    &session_url,
                )
                .await);
        }
        let location = header_str(&response, &LOCATION)
            .ok_or_else(|| anyhow!("registry returned no Location for blob upload session"))?;
        let put_url =
            append_query_param(&resolve_location(&self.base, &location), "digest", digest);
        let response = self
            .request_with_auth(
                Method::PUT,
                &put_url,
                &scope,
                &[(
                    CONTENT_TYPE,
                    HeaderValue::from_static(MEDIA_TYPE_OCTET_STREAM),
                )],
                body,
                self.upload_timeout,
            )
            .await?;
        if !response.status().is_success() {
            return Err(self
                .error_for_status(
                    response,
                    &format!("blob upload of {digest} to {repo}"),
                    &put_url,
                )
                .await);
        }
        Ok(())
    }

    /// Best-effort DELETE of an unwanted upload session (e.g. one opened by a
    /// declined cross-repo mount). Failures are logged and ignored — the
    /// registry garbage-collects stale sessions anyway.
    async fn cancel_upload(&self, repo: &str, location: &str) {
        let url = resolve_location(&self.base, location);
        match self
            .request_with_auth(
                Method::DELETE,
                &url,
                &push_scope(repo),
                &[],
                BodySource::Empty,
                self.timeout,
            )
            .await
        {
            Ok(response) => {
                debug!(%url, status = %response.status(), "cancelled unused blob upload session")
            }
            Err(e) => debug!(%url, error = %e, "failed to cancel unused blob upload session"),
        }
    }

    /// Compute a file's `sha256:<hex>` digest by streaming it in
    /// [`FILE_HASH_CHUNK`] pieces.
    async fn file_digest(&self, path: &Path) -> Result<String> {
        let file = compio::fs::File::open(path)
            .await
            .with_context(|| format!("open blob file {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut pos = 0u64;
        let mut buf = Vec::with_capacity(FILE_HASH_CHUNK);
        loop {
            let BufResult(read_result, returned) = file.read_at(buf, pos).await;
            buf = returned;
            let n = read_result.with_context(|| format!("read blob file {}", path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            pos += n as u64;
            buf.clear();
        }
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    /// Send a request through the 401 → challenge → token → retry-once flow.
    ///
    /// The first attempt carries a cached bearer token for `scope` (if any),
    /// else basic auth (if configured), else nothing. On `401`, the
    /// `WWW-Authenticate` challenge of THAT response drives a token fetch
    /// (the challenge's own scope wins over `scope` when present), the token
    /// is cached, and the request is retried exactly once. Non-401 responses
    /// — including errors — are returned as-is for the caller to interpret.
    async fn request_with_auth(
        &self,
        method: Method,
        url: &str,
        scope: &str,
        headers: &[(HeaderName, HeaderValue)],
        body: BodySource<'_>,
        timeout: Option<Duration>,
    ) -> Result<Response, RegistryError> {
        let initial_auth = self.initial_auth_header(scope)?;
        let response = self
            .send_once(method.clone(), url, headers, &body, initial_auth, timeout)
            .await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let Some(challenge) = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_bearer_challenge)
        else {
            // Basic-only (or absent) challenge: the first attempt already sent
            // basic auth when available, so there is nothing left to try.
            return Ok(response);
        };
        let header = self.acquire_bearer(&challenge, scope).await?;
        self.send_once(method, url, headers, &body, Some(header), timeout)
            .await
    }

    /// Fetch and cache a bearer token for `challenge`, preferring the
    /// challenge's scope over the caller-requested one. Failures map to
    /// [`RegistryError::Auth`] — a broken token dance is an auth failure,
    /// whatever its underlying transport shape.
    async fn acquire_bearer(
        &self,
        challenge: &BearerChallenge,
        requested_scope: &str,
    ) -> Result<HeaderValue, RegistryError> {
        let token_scope = challenge
            .scope
            .clone()
            .unwrap_or_else(|| requested_scope.to_string());
        let bearer = fetch_bearer_token(
            &self.client,
            challenge,
            &token_scope,
            self.basic_auth.as_deref(),
            self.timeout,
        )
        .await
        .map_err(|e| RegistryError::Auth(format!("bearer token fetch failed: {e:#}")))?;
        {
            let mut cache = self.tokens.borrow_mut();
            cache.insert(requested_scope, &bearer.token, bearer.expires_in);
            if token_scope != requested_scope {
                cache.insert(&token_scope, &bearer.token, bearer.expires_in);
            }
        }
        HeaderValue::from_str(&format!("Bearer {}", bearer.token)).map_err(|_| {
            RegistryError::Auth("registry bearer token contained invalid header characters".into())
        })
    }

    /// One attempt: build the request (headers, optional auth, body) and send
    /// it with the per-request timeout.
    async fn send_once(
        &self,
        method: Method,
        url: &str,
        headers: &[(HeaderName, HeaderValue)],
        body: &BodySource<'_>,
        auth: Option<HeaderValue>,
        timeout: Option<Duration>,
    ) -> Result<Response, RegistryError> {
        let mut request = self
            .client
            .request(method, url)
            .with_context(|| format!("invalid registry request URL {url}"))?;
        for (name, value) in headers {
            request = request
                .header(name.clone(), value.clone())
                .with_context(|| format!("invalid {name} header"))?;
        }
        if let Some(auth) = auth {
            // Registries may redirect uploads/blobs to a third-party host
            // (S3, CDN) via an absolute `Location`. The registry credential's
            // audience is the registry origin only — forwarding it
            // cross-origin would leak it to whatever host the registry names
            // (presigned URLs carry their own authorization in the query).
            if same_origin(&self.base, url) {
                request = request
                    .header(AUTHORIZATION, auth)
                    .context("invalid Authorization header")?;
            } else {
                debug!(
                    url,
                    "cross-origin registry redirect: not forwarding Authorization"
                );
            }
        }
        request = match body {
            BodySource::Empty => request,
            BodySource::Bytes(bytes) => request.body(bytes.to_vec()),
            BodySource::File(path) => {
                let file = compio::fs::File::open(path)
                    .await
                    .with_context(|| format!("open upload file {}", path.display()))?;
                let len = file
                    .metadata()
                    .await
                    .with_context(|| format!("stat upload file {}", path.display()))?
                    .len();
                // Explicit Content-Length: hyper then uses length framing for
                // the streamed body, as monolithic uploads require.
                request
                    .header(CONTENT_LENGTH, HeaderValue::from(len))
                    .context("invalid Content-Length header")?
                    .body(file)
            }
        };
        let send = request.send();
        match timeout {
            Some(duration) => compio::time::timeout(duration, send)
                .await
                .map_err(|_| RegistryError::Timeout(format!("registry request to {url}")))?,
            None => send.await,
        }
        .with_context(|| format!("registry request failed for {url}"))
        .map_err(RegistryError::from)
    }

    /// Best available `Authorization` header for the first attempt: cached
    /// bearer token for `scope`, else basic auth, else none.
    fn initial_auth_header(&self, scope: &str) -> Result<Option<HeaderValue>> {
        if let Some(token) = self.tokens.borrow().get(scope) {
            return Ok(Some(
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .context("cached bearer token contained invalid header characters")?,
            ));
        }
        self.basic_auth
            .as_deref()
            .map(auth_header_value)
            .transpose()
    }

    fn manifest_url(&self, repo: &str, reference: &str) -> String {
        format!("{}/v2/{repo}/manifests/{reference}", self.base)
    }

    fn blob_url(&self, repo: &str, digest: &str) -> String {
        format!("{}/v2/{repo}/blobs/{digest}", self.base)
    }

    fn upload_url(&self, repo: &str) -> String {
        format!("{}/v2/{repo}/blobs/uploads/", self.base)
    }

    fn referrers_url(&self, repo: &str, digest: &str) -> String {
        format!("{}/v2/{repo}/referrers/{digest}", self.base)
    }
}

/// Client-side `artifactType` filter for a referrers index. The OCI 1.1 spec
/// permits servers to ignore the `artifactType` query parameter (a compliant
/// server that applied it sets `OCI-Filters-Applied`, but that header is
/// advisory), so the requested filter must always be re-applied locally.
/// Descriptors without an `artifactType` are dropped when filtering.
pub fn filter_referrers(index: &mut Index, artifact_type: &str) {
    index
        .manifests
        .retain(|desc| desc.artifact_type.as_deref() == Some(artifact_type));
}

/// Read a response header as an owned string.
fn header_str(response: &Response, name: &HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// Resolve an upload `Location` header against the registry base URL
/// (`scheme://host[:port]`, no trailing slash). Absolute locations pass
/// through untouched; relative ones (with or without a leading `/`) are
/// joined onto the base, preserving any query string they carry.
/// Whether `url` targets the same origin (`scheme://host[:port]`) as `base`.
///
/// `base` is already a bare origin with no trailing slash (see
/// [`RegistryClient`] construction), so this reduces to extracting `url`'s
/// origin — everything up to the first `/` after the scheme separator — and
/// comparing case-insensitively. Ports are compared literally: a registry
/// that names its own origin differently than `base` was configured (implicit
/// vs explicit default port) fails closed, which only means credentials are
/// withheld from a URL we cannot prove is the registry itself.
fn same_origin(base: &str, url: &str) -> bool {
    fn origin_of(u: &str) -> Option<&str> {
        let scheme_end = u.find("://")? + 3;
        let path_start = u[scheme_end..]
            .find('/')
            .map(|i| scheme_end + i)
            .unwrap_or(u.len());
        Some(&u[..path_start])
    }
    match (origin_of(base), origin_of(url)) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

pub fn resolve_location(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with('/') {
        format!("{base}{location}")
    } else {
        format!("{base}/{location}")
    }
}

/// Append `key=value` to a URL's query string, using `?` or `&` depending on
/// whether the URL already has query parameters. The value is
/// percent-encoded, so digests (`sha256:...`) are safe.
pub fn append_query_param(url: &str, key: &str, value: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{key}={}", percent_encode_query(value))
}

/// Read a response body into memory, enforcing `max_bytes` **while
/// streaming** rather than after the fact.
///
/// A `Content-Length` pre-check alone cannot stop a registry that omits or
/// lies about the header, or that uses chunked transfer-encoding (no length
/// header at all). So the body is read chunk-by-chunk via
/// [`Response::bytes_stream`] through [`collect_bounded`], which tracks the
/// running total and bails the moment it crosses `max_bytes` — at most one
/// in-flight chunk over the cap is ever buffered, regardless of what the
/// registry claims or how it frames the response.
///
/// The `Content-Length` check is a cheap fast-path rejection (skip opening
/// the stream at all when the registry honestly advertises an oversized body
/// up front); it is not load-bearing for the guarantee above.
async fn read_bounded(
    response: Response,
    url: &str,
    max_bytes: u64,
    deadline: Option<Duration>,
) -> Result<Vec<u8>, RegistryError> {
    if let Some(len) = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        && len > max_bytes
    {
        return Err(RegistryError::Other(anyhow!(
            "registry body at {url} of {len} bytes exceeds cap of {max_bytes} bytes"
        )));
    }
    // The byte cap alone does not bound TIME: a slow-drip body trickling in
    // just fast enough to keep individual reads alive could hold the caller
    // indefinitely while staying under the cap. The deadline bounds the whole
    // body read wall-clock.
    let collect = collect_bounded(response.bytes_stream(), max_bytes, url);
    let bytes = match deadline {
        Some(limit) => compio::time::timeout(limit, collect).await.map_err(|_| {
            RegistryError::Timeout(format!(
                "reading registry body at {url} exceeded {limit:?} deadline"
            ))
        })?,
        None => collect.await,
    }?;
    Ok(bytes)
}

/// Collect a byte stream into memory, bailing the moment the running total
/// exceeds `max_bytes` — checked chunk-by-chunk as bytes arrive, never after
/// a full collect. `label` identifies the source (typically the request URL)
/// for the error message.
///
/// Generic over the chunk type (anything `AsRef<[u8]>`, e.g. `bytes::Bytes`
/// as yielded by [`Response::bytes_stream`]) and the stream's error type, so
/// it needs no direct dependency on the `bytes` crate and tests can drive it
/// with a plain `futures::stream::iter` of `Vec<u8>` chunks. The stream is
/// boxed internally so callers don't need to prove `Unpin` themselves.
async fn collect_bounded<S, B, E>(stream: S, max_bytes: u64, label: &str) -> Result<Vec<u8>>
where
    S: futures::Stream<Item = std::result::Result<B, E>>,
    B: AsRef<[u8]>,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut stream = Box::pin(stream);
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("read chunk while streaming {label}"))?;
        let chunk = chunk.as_ref();
        if buf.len() as u64 + chunk.len() as u64 > max_bytes {
            bail!("{label} exceeds cap of {max_bytes} bytes");
        }
        buf.extend_from_slice(chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client(plain_http: bool) -> RegistryClient {
        RegistryClient::new(
            "registry.local:5000",
            RegistryClientOptions {
                plain_http,
                // Never read the developer's real ~/.docker/config.json in tests.
                use_docker_config: false,
                ..RegistryClientOptions::default()
            },
        )
        .unwrap()
    }

    #[compio::test]
    async fn urls_follow_the_distribution_spec() {
        let client = test_client(false);
        assert_eq!(
            client.manifest_url("team/app", "1.2.3"),
            "https://registry.local:5000/v2/team/app/manifests/1.2.3"
        );
        assert_eq!(
            client.blob_url("team/app", "sha256:abc"),
            "https://registry.local:5000/v2/team/app/blobs/sha256:abc"
        );
        assert_eq!(
            client.upload_url("team/app"),
            "https://registry.local:5000/v2/team/app/blobs/uploads/"
        );
        assert_eq!(
            client.referrers_url("team/app", "sha256:abc"),
            "https://registry.local:5000/v2/team/app/referrers/sha256:abc"
        );
        // The artifactType query filter is percent-encoded like any other
        // query value.
        assert_eq!(
            append_query_param(
                &client.referrers_url("team/app", "sha256:abc"),
                "artifactType",
                "application/vnd.oci.image.layer.nydus.blob.v1"
            ),
            "https://registry.local:5000/v2/team/app/referrers/sha256:abc?artifactType=application%2Fvnd.oci.image.layer.nydus.blob.v1"
        );
    }

    /// The referrers response shape from the OCI distribution spec 1.1: an
    /// image index whose manifests[] are artifact descriptors carrying
    /// `artifactType` and `annotations`.
    const REFERRERS_INDEX_JSON: &str = r#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:nydusartifact000000000000000000000000000000000000000000000000000",
                "size": 1234,
                "artifactType": "application/vnd.oci.image.layer.nydus.blob.v1",
                "annotations": {"containerd.io/snapshot/nydus-fs-driver": "fanotify"}
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:sbomartifact0000000000000000000000000000000000000000000000000000",
                "size": 5678,
                "artifactType": "application/spdx+json"
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:untyped000000000000000000000000000000000000000000000000000000000",
                "size": 9
            }
        ]
    }"#;

    #[test]
    fn referrers_index_parses_artifact_descriptors() {
        let index: Index = serde_json::from_str(REFERRERS_INDEX_JSON).unwrap();
        assert_eq!(index.schema_version, 2);
        assert_eq!(
            index.media_type.as_deref(),
            Some("application/vnd.oci.image.index.v1+json")
        );
        assert_eq!(index.manifests.len(), 3);
        let nydus = &index.manifests[0];
        assert_eq!(
            nydus.artifact_type.as_deref(),
            Some("application/vnd.oci.image.layer.nydus.blob.v1")
        );
        assert_eq!(
            nydus
                .annotations
                .as_ref()
                .unwrap()
                .get("containerd.io/snapshot/nydus-fs-driver")
                .map(String::as_str),
            Some("fanotify")
        );
        // Absent artifactType parses as None, not an error.
        assert!(index.manifests[2].artifact_type.is_none());
    }

    #[test]
    fn filter_referrers_is_applied_client_side() {
        // The server may ignore the artifactType query filter entirely, so the
        // client-side filter must reduce a mixed index to exact matches only.
        let mut index: Index = serde_json::from_str(REFERRERS_INDEX_JSON).unwrap();
        filter_referrers(&mut index, "application/vnd.oci.image.layer.nydus.blob.v1");
        assert_eq!(index.manifests.len(), 1);
        assert!(
            index.manifests[0]
                .digest
                .starts_with("sha256:nydusartifact")
        );

        // No matches (including descriptors without any artifactType) leaves
        // an empty, still-valid index.
        let mut index: Index = serde_json::from_str(REFERRERS_INDEX_JSON).unwrap();
        filter_referrers(&mut index, "application/vnd.example.other");
        assert!(index.manifests.is_empty());
    }

    #[compio::test]
    async fn plain_http_switches_scheme() {
        let client = test_client(true);
        assert!(client.manifest_url("a/b", "1").starts_with("http://"));
    }

    #[compio::test]
    async fn explicit_credentials_take_precedence_and_become_basic_auth() {
        let client = RegistryClient::new(
            "registry.local:5000",
            RegistryClientOptions {
                credentials: Some(Credentials {
                    username: "user".into(),
                    password: "pass".into(),
                }),
                use_docker_config: false,
                ..RegistryClientOptions::default()
            },
        )
        .unwrap();
        let header = client.initial_auth_header("repository:a:pull").unwrap();
        assert_eq!(
            header.unwrap(),
            format!("Basic {}", {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode("user:pass")
            })
        );
    }

    #[compio::test]
    async fn cached_token_wins_over_basic_auth() {
        let client = test_client(false);
        assert!(
            client
                .initial_auth_header("repository:a:pull")
                .unwrap()
                .is_none()
        );
        client
            .tokens
            .borrow_mut()
            .insert("repository:a:pull", "tok", Some(300));
        assert_eq!(
            client
                .initial_auth_header("repository:a:pull")
                .unwrap()
                .unwrap(),
            "Bearer tok"
        );
    }

    #[test]
    fn same_origin_matches_scheme_host_port_only() {
        assert!(same_origin(
            "https://registry.local:5000",
            "https://registry.local:5000/v2/foo/blobs/uploads/x?digest=y"
        ));
        assert!(same_origin(
            "https://Registry.Local",
            "https://registry.local/v2/"
        ));
        // Host-prefix confusion must not pass.
        assert!(!same_origin(
            "https://registry.local",
            "https://registry.local.evil.example/v2/"
        ));
        // Redirects to object storage lose the credential.
        assert!(!same_origin(
            "https://registry.local:5000",
            "https://bucket.s3.amazonaws.com/presigned"
        ));
        // Scheme downgrades are a different origin too.
        assert!(!same_origin(
            "https://registry.local",
            "http://registry.local/v2/"
        ));
    }

    #[test]
    fn resolve_location_handles_absolute_and_relative() {
        let base = "https://registry.local:5000";
        // Absolute: pass through (possibly to a different host, e.g. S3).
        assert_eq!(
            resolve_location(base, "https://cdn.example/upload/xyz?token=1"),
            "https://cdn.example/upload/xyz?token=1"
        );
        // Relative with leading slash (registry:2's shape).
        assert_eq!(
            resolve_location(base, "/v2/repo/blobs/uploads/uuid?_state=abc"),
            "https://registry.local:5000/v2/repo/blobs/uploads/uuid?_state=abc"
        );
        // Relative without leading slash.
        assert_eq!(
            resolve_location(base, "v2/repo/blobs/uploads/uuid"),
            "https://registry.local:5000/v2/repo/blobs/uploads/uuid"
        );
    }

    #[test]
    fn append_query_param_uses_question_mark_or_ampersand() {
        // No existing query: `?`.
        assert_eq!(
            append_query_param("https://r/v2/x/blobs/uploads/u", "digest", "sha256:abc"),
            "https://r/v2/x/blobs/uploads/u?digest=sha256%3Aabc"
        );
        // Existing query (registry:2's `?_state=`): `&`.
        assert_eq!(
            append_query_param(
                "https://r/v2/x/blobs/uploads/u?_state=s1",
                "digest",
                "sha256:abc"
            ),
            "https://r/v2/x/blobs/uploads/u?_state=s1&digest=sha256%3Aabc"
        );
        // Chained parameters (the mount case).
        let mounted = append_query_param(
            &append_query_param("https://r/v2/x/blobs/uploads/", "mount", "sha256:abc"),
            "from",
            "team/base",
        );
        assert_eq!(
            mounted,
            "https://r/v2/x/blobs/uploads/?mount=sha256%3Aabc&from=team%2Fbase"
        );
    }

    #[compio::test]
    async fn file_digest_matches_bytes_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.bin");
        // Larger than one hash chunk so the loop iterates.
        let data = vec![0xa7u8; FILE_HASH_CHUNK + 4096];
        std::fs::write(&path, &data).unwrap();
        let client = test_client(false);
        assert_eq!(
            client.file_digest(&path).await.unwrap(),
            sha256_digest(&data)
        );
    }

    #[compio::test]
    async fn read_deadline_bounds_a_stalled_body() {
        // A stream that never yields models a slow-drip/stalled body; the
        // wall-clock deadline must fire instead of waiting forever.
        let stream = futures::stream::pending::<std::result::Result<Vec<u8>, std::io::Error>>();
        let collect = collect_bounded(stream, 1024, "https://registry.local/v2/x");
        let res = compio::time::timeout(Duration::from_millis(20), collect).await;
        assert!(res.is_err(), "deadline should fire on a stalled stream");
    }

    #[compio::test]
    async fn collect_bounded_bails_as_soon_as_running_total_exceeds_cap() {
        // Three 10-byte chunks against a 25-byte cap: the running total
        // crosses the cap on the third chunk (30 > 25), so the call must
        // bail there rather than after collecting all chunks.
        let chunks: Vec<std::result::Result<Vec<u8>, std::io::Error>> =
            vec![Ok(vec![0u8; 10]), Ok(vec![0u8; 10]), Ok(vec![0u8; 10])];
        let stream = futures::stream::iter(chunks);
        let err = collect_bounded(stream, 25, "https://registry.local/v2/x/blobs/sha256:abc")
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("exceeds cap of 25 bytes"), "{message}");
        assert!(
            message.contains("https://registry.local/v2/x/blobs/sha256:abc"),
            "{message}"
        );
    }

    #[compio::test]
    async fn collect_bounded_accepts_a_body_exactly_at_the_cap() {
        let chunks: Vec<std::result::Result<Vec<u8>, std::io::Error>> =
            vec![Ok(vec![1u8; 10]), Ok(vec![2u8; 10])];
        let stream = futures::stream::iter(chunks);
        let bytes = collect_bounded(stream, 20, "test").await.unwrap();
        assert_eq!(bytes.len(), 20);
        assert_eq!(&bytes[..10], &[1u8; 10]);
        assert_eq!(&bytes[10..], &[2u8; 10]);
    }

    #[compio::test]
    async fn collect_bounded_never_had_content_length_to_lean_on() {
        // With no Content-Length header at all (chunked transfer-encoding),
        // the cap must be enforced purely from the running total of streamed
        // chunks. A body one byte over the cap is rejected even though no
        // length header was ever consulted.
        let cap = 1024u64;
        let chunks: Vec<std::result::Result<Vec<u8>, std::io::Error>> =
            vec![Ok(vec![0u8; 1024]), Ok(vec![0u8; 1])];
        let stream = futures::stream::iter(chunks);
        let err = collect_bounded(stream, cap, "chunked body")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds cap of 1024 bytes"));
    }

    #[test]
    fn default_options_are_secure_and_time_bounded() {
        let opts = RegistryClientOptions::default();
        assert!(!opts.plain_http);
        assert!(!opts.insecure_tls);
        assert_eq!(opts.timeout, Some(Duration::from_secs(30)));
        assert!(opts.upload_timeout.is_none());
        assert!(opts.use_docker_config);
    }
}
