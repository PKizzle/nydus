// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Image-ref lookup by inspecting containerd's image store.
//!
//! containerd 2.x (as shipped in k3s ≥ v1.36) does not forward the
//! `containerd.io/snapshot/cri.image-ref` label to proxy-plugin snapshotters
//! at container Prepare time. To still name the image behind a snapshot
//! chainID (or Nydus bootstrap blob digest) we walk every image containerd
//! knows in the snapshot's namespace and record which images claim which
//! digests.
//!
//! A chainID names layer content, not an image. A repository is the unit of
//! trust (its publisher decides what its tags point at), so the targets a
//! repository's tag records name are one claimant. A target only digest records name is a claimant of its own: a
//! digest names content, not a publisher's choice. The lookup answers
//! [`Claim::Ambiguous`] when a digest has more than one claimant (or an image
//! known only by its ID claims it next to a named one); callers serve nothing
//! image-specific for it.
//!
//! Every lookup answers from a listing of the namespace's image records
//! (`Images.List`, one RPC) started after the lookup was called, so a
//! claimant pulled before the call is never missed. Walks are memoized by
//! record target digest: a target names immutable content, so only targets
//! not seen before cost `Content.Read`s. Image JSON is read as containerd's Go
//! decoder reads it ([`go_json`]). A target that cannot be walked is kept as
//! unknown and makes every claim it could change uncertain (an error), never a
//! smaller claimant set, unless its content is absent or containerd could not
//! parse it either (no container can be created from it). Refreshes are single-flight per
//! namespace, and lookups that arrive while one runs share the next listing,
//! success or failure, so a burst of N lookups costs two listings rather than
//! N.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::content_store::{ContentStoreClient, is_not_found, is_rpc_failure};

/// Acquire a lock without panicking on poisoning. A previous panic while a
/// lock was held would only have left the memo in a partially-populated
/// state; the next refresh rebuilds it.
fn lock_cache<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

const NYDUS_BOOTSTRAP_ANNOTATION: &str = "containerd.io/snapshot/nydus-bootstrap";

/// How long a target whose content could not be read is not walked again.
/// It stays uncertain meanwhile; a transport failure is retried on the next
/// listing.
const WALK_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// The containerd namespace of a proxy-plugin snapshot key
/// (`<namespace>/<id>/<name>`); `None` for a key without one.
pub fn namespace_of_key(key: &str) -> Option<&str> {
    let (namespace, rest) = key.split_once('/')?;
    (!namespace.is_empty() && rest.contains('/')).then_some(namespace)
}

/// Which images claim a digest (a chainID or a nydus bootstrap layer digest)
/// in one containerd namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Claim {
    /// No image record names a repository for it.
    Unclaimed,
    /// One claimant: the tag-named targets of one repository, or one target
    /// only digest records name.
    One(Claimant),
    /// Several claimants, or an image known only by its ID next to a named
    /// one: each claiming repository (`repo@<target>` for a digest-only
    /// target), sorted. Nothing tells which one a container was created from.
    Ambiguous(Vec<String>),
}

/// The one claimant of a digest: the targets one repository's tags name, all
/// from one publisher, so any of them may answer for the others; or a single
/// target only digest records name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claimant {
    /// `host/repo` of every claiming image record.
    pub repository: String,
    /// The claiming images, the most recently updated record first, then by
    /// name. Never empty.
    pub images: Vec<ClaimedImage>,
}

/// One image record target claiming a digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedImage {
    /// Its best record name in the repository (a tag over a digest ref).
    pub image_ref: String,
    /// The record's target: the index or manifest digest the image was
    /// pulled as, which the content store holds.
    pub target: String,
}

impl Claimant {
    /// The name to serve the claimant under: the first image's.
    pub fn image_ref(&self) -> &str {
        &self.images[0].image_ref
    }

    /// Whether `image_ref` names an image of this claimant's repository.
    pub fn admits(&self, image_ref: &str) -> bool {
        repository(image_ref) == Some(self.repository.as_str())
    }

    /// Whether the claimant is its repository's tag-named targets (not one
    /// target only digest records name).
    fn by_tag(&self) -> bool {
        is_tag_ref(self.image_ref())
    }
}

/// Whether a record name is a tag-form ref (`host/repo:tag`).
fn is_tag_ref(name: &str) -> bool {
    ref_name_rank(name) == 3
}

/// A target whose record names include a tag.
fn tag_named(names: &[String]) -> bool {
    names.iter().any(|n| is_tag_ref(n))
}

/// Image JSON that containerd's decoder rejects as well (see [`go_json`]):
/// no container can be created from it.
#[derive(Debug, thiserror::Error)]
#[error("unparsable image JSON: {0}")]
struct Unparsable(String);

fn is_unparsable(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<Unparsable>())
}

/// Parse image JSON (an index, manifest or config) as containerd's Go
/// decoder (`encoding/json`) does, so the walk sees what containerd uses: a
/// later duplicate key wins, invalid UTF-8 reads as U+FFFD, and a `null`
/// member leaves its field at the default. JSON this rejects is
/// [`Unparsable`].
fn go_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    fn drop_null_members(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                map.retain(|_, v| !v.is_null());
                map.values_mut().for_each(drop_null_members);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(drop_null_members),
            _ => {}
        }
    }
    let mut value: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(bytes))
        .map_err(|e| Unparsable(e.to_string()))?;
    drop_null_members(&mut value);
    Ok(serde_json::from_value(value).map_err(|e| Unparsable(e.to_string()))?)
}

/// The repository part of an image ref (`host/repo` of `host/repo:tag` or
/// `host/repo@sha256:…`); `None` for a bare image-ID ref.
fn repository(image_ref: &str) -> Option<&str> {
    if ref_name_rank(image_ref) == 0 {
        return None;
    }
    let name = image_ref
        .split_once('@')
        .map_or(image_ref, |(name, _)| name);
    Some(match name.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => repo,
        _ => name,
    })
}

/// The repositories among an image's record names.
fn repositories(names: &[String]) -> BTreeSet<&str> {
    names.iter().filter_map(|n| repository(n)).collect()
}

/// Record update time (seconds, nanoseconds since the epoch).
type Updated = (i64, i32);

/// The digests one image record target claims.
#[derive(Clone, Debug)]
struct TargetWalk {
    /// Every record name pointing at the target, sorted.
    names: Vec<String>,
    updated: Updated,
    digests: BTreeSet<String>,
}

/// A target whose walk failed: what it claims is unknown.
#[derive(Clone, Debug)]
struct WalkFailure {
    names: Vec<String>,
    /// The record update the walk failed for; a newer one is walked again.
    updated: Updated,
    retry_at: Instant,
    /// Its content is absent from the content store, or containerd could not
    /// parse it either. CRI resolves an image's manifest and config from there
    /// to create a container, so no container being prepared can come from
    /// it, and it claims nothing.
    absent: bool,
    error: String,
}

/// The claims memo of one namespace, rebuilt from every listing.
#[derive(Default)]
struct Memo {
    walks: BTreeMap<String, TargetWalk>,
    failed: BTreeMap<String, WalkFailure>,
}

/// A finished listing's id and outcome.
type FinishedListing = (u64, Result<(), Arc<anyhow::Error>>);

/// One namespace's memo and refresh state.
#[derive(Default)]
struct NamespaceClaims {
    memo: Mutex<Memo>,
    /// Single-flight gate for refreshes.
    gate: async_lock::Mutex<()>,
    /// Number of listings started; a listing's id is the count after its start.
    started: AtomicU64,
    /// The latest finished listing.
    finished: Mutex<Option<FinishedListing>>,
}

#[derive(Default)]
pub struct ContainerdLookup {
    /// Claims per containerd namespace, created on first use.
    namespaces: Mutex<HashMap<String, Arc<NamespaceClaims>>>,
    /// gRPC client for containerd's Images + Content services. `None` only
    /// in legacy constructions: chain lookups then find nothing, and
    /// `manifest_info` falls back to the `crictl` / `ctr` CLI.
    content_store: Option<ContentStoreClient>,
}
#[derive(Deserialize)]
struct CrictlImages {
    images: Vec<CrictlImage>,
}

#[derive(Deserialize, Default)]
struct CrictlImage {
    #[serde(default)]
    #[serde(rename = "repoTags")]
    repo_tags: Vec<String>,
    #[serde(default)]
    #[serde(rename = "repoDigests")]
    repo_digests: Vec<String>,
}

#[derive(Deserialize)]
struct OciManifest {
    #[serde(default)]
    layers: Vec<OciDescriptor>,
    #[serde(default)]
    config: Option<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    digest: String,
    #[serde(default)]
    annotations: HashMap<String, String>,
    #[serde(default, rename = "mediaType")]
    media_type: String,
}

#[derive(Deserialize)]
struct OciImageConfig {
    /// Absent from a manifest that only carries metadata under a non-empty config media type
    /// (some buildx attestation manifests, a bare `{}` config): like an OCI artifact, it has no
    /// chainIDs to register.
    #[serde(default)]
    rootfs: OciRootfs,
}

#[derive(Default, Deserialize)]
struct OciRootfs {
    #[serde(default, rename = "diff_ids")]
    diff_ids: Vec<String>,
}

impl ContainerdLookup {
    /// Construct with a containerd gRPC client (preferred — all reads go
    /// through Images.List / Content.Read, no subprocess spawns).
    pub fn new(content_store: ContentStoreClient) -> Self {
        Self {
            content_store: Some(content_store),
            ..Self::default()
        }
    }

    /// Legacy construction without a gRPC client: chain lookups find
    /// nothing and `manifest_info` runs `crictl` / `ctr` subprocesses (on
    /// the blocking pool).
    pub fn new_cli_only() -> Self {
        Self::default()
    }

    /// Which images in `namespace` claim `digest` (a topmost chainID or a
    /// nydus bootstrap layer digest), from a listing of the namespace's image
    /// store taken by this call. `Err` means the answer is unknown: the store
    /// could not be listed, or an image whose content could not be read might
    /// change it. Callers must not take that for a miss, and must not serve
    /// anything image-specific either.
    pub async fn lookup(&self, namespace: &str, digest: &str) -> Result<Claim> {
        self.refresh(namespace).await?;
        let claim = self.lookup_cached(namespace, digest)?;
        if claim == Claim::Unclaimed {
            info!(namespace, digest, "no containerd image claims this digest");
        }
        Ok(claim)
    }

    /// Memo-only [`lookup`]: never walks containerd and never blocks, so a
    /// caller that serves with the answer runs `lookup` first.
    ///
    /// [`lookup`]: Self::lookup
    pub fn lookup_cached(&self, namespace: &str, digest: &str) -> Result<Claim> {
        let state = self.namespace(namespace);
        let memo = lock_cache(&state.memo);
        let claim = claim_of(&memo.walks, digest);
        // Only another tag-named target of a tag claimant's repository joins
        // that claimant; any other unwalked target could make it ambiguous.
        if let Claim::One(claimant) = &claim
            && let Some((target, failure)) = memo.failed.iter().find(|(_, f)| {
                let repos = repositories(&f.names);
                let joins = claimant.by_tag()
                    && tag_named(&f.names)
                    && repos.len() == 1
                    && repos.contains(claimant.repository.as_str());
                !f.absent && !joins
            })
        {
            bail!(
                "image {target} ({}) could not be walked, so it may also claim {digest}: {}",
                failure.names.join(", "),
                failure.error
            );
        }
        Ok(claim)
    }

    /// The claim of the walked targets alone, whatever targets could not be
    /// walked: for a caller whose served content does not depend on which
    /// claimant a container came from. Never walks containerd; a caller runs
    /// [`refresh`] first.
    ///
    /// [`refresh`]: Self::refresh
    pub fn lookup_walked(&self, namespace: &str, digest: &str) -> Claim {
        claim_of(&lock_cache(&self.namespace(namespace).memo).walks, digest)
    }

    fn namespace(&self, namespace: &str) -> Arc<NamespaceClaims> {
        lock_cache(&self.namespaces)
            .entry(namespace.to_string())
            .or_default()
            .clone()
    }

    /// List `namespace`'s image records and bring its memo in line with
    /// them, unless a listing that started after this call already finished:
    /// its outcome, success or failure, is this call's.
    pub async fn refresh(&self, namespace: &str) -> Result<()> {
        let state = self.namespace(namespace);
        // A listing with a higher id than this started after this call did,
        // so it saw every record this call could need.
        let arrived = state.started.load(Ordering::SeqCst);
        let _gate = state.gate.lock().await;
        if let Some((id, outcome)) = &*lock_cache(&state.finished)
            && *id > arrived
        {
            return outcome
                .clone()
                .map_err(|e| anyhow!("containerd image listing failed: {e:#}"));
        }
        let Some(cs) = &self.content_store else {
            return Ok(());
        };
        let listing = state.started.fetch_add(1, Ordering::SeqCst) + 1;
        let result = refresh_memo(&cs.with_namespace(namespace), &state.memo).await;
        *lock_cache(&state.finished) = Some((
            listing,
            match &result {
                Ok(()) => Ok(()),
                Err(e) => Err(Arc::new(anyhow!("{e:#}"))),
            },
        ));
        result
    }

    /// Forward direction: resolve an image reference to its manifest digest
    /// and ordered layer list (lower→upper), with each layer's on-disk
    /// path in containerd's content store. Returns an error if the image
    /// isn't known to containerd, has no compatible architecture in a
    /// multi-arch index, or carries no layers node-local acceleration reads.
    ///
    /// This is on-demand (not cached); the conversion path needs a single
    /// resolution per image and the call cost is two or three Content.Read
    /// RPCs for the manifest/index/config blobs.
    pub async fn manifest_info(
        &self,
        image_ref: &str,
        content_root: &std::path::Path,
    ) -> Result<ManifestInfo> {
        match &self.content_store {
            Some(cs) => {
                self.manifest_info_via_grpc(cs, image_ref, content_root)
                    .await
            }
            None => {
                let image_ref = image_ref.to_string();
                let content_root = content_root.to_path_buf();
                blocking::unblock(move || manifest_info_via_cli(&image_ref, &content_root)).await
            }
        }
    }

    async fn manifest_info_via_grpc(
        &self,
        cs: &ContentStoreClient,
        image_ref: &str,
        content_root: &std::path::Path,
    ) -> Result<ManifestInfo> {
        // Exact-name fast path first (`name:tag` / `name@sha256:...`).
        let target = match cs.images_get(image_ref).await? {
            Some(info) => Some(info.digest),
            None => {
                // The ref may be name-only (`docker.io/library/nginx`) —
                // match it against the name part of every record, exactly
                // like the legacy crictl matcher did.
                let records = cs.images_list().await.context("containerd Images.List")?;
                records
                    .iter()
                    .find(|r| record_matches_ref(&r.name, image_ref))
                    .map(|r| r.target_digest.clone())
            }
        };
        let Some(target) = target else {
            bail!(
                "image {image_ref} not found in containerd image store; \
                 make sure it's been pulled at least once"
            );
        };
        resolve_accel_layers_via_grpc(cs, &target, content_root).await
    }
}

/// One containerd image record (name + manifest/index target digest).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageRecord {
    pub name: String,
    pub target_digest: String,
    /// When the record was last updated (seconds, nanoseconds).
    pub updated: (i64, i32),
}

/// The records pointing at one target.
struct RecordGroup {
    target: String,
    /// Every record name, sorted.
    names: Vec<String>,
    /// The latest update of any of them.
    updated: Updated,
}

/// Bring `memo` in line with `cs`'s image records: walk targets not seen
/// before, keep the walks of listed targets, drop targets no longer listed.
/// A target whose walk fails is kept as a failure, retried on the next
/// listing after a transport error, and otherwise once its record is updated
/// or [`WALK_RETRY_INTERVAL`] has passed.
async fn refresh_memo(cs: &ContentStoreClient, memo: &Mutex<Memo>) -> Result<()> {
    let records = cs.images_list().await.context("containerd Images.List")?;
    let (mut walked, mut failed) = (0, 0);
    let mut fresh = Memo::default();
    for group in group_records_by_target(&records) {
        let (known, failure) = {
            let memo = lock_cache(memo);
            (
                memo.walks.get(&group.target).map(|w| w.digests.clone()),
                memo.failed
                    .get(&group.target)
                    .filter(|f| f.retry_at > Instant::now() && f.updated == group.updated)
                    .cloned(),
            )
        };
        let digests = match (known, failure) {
            (Some(digests), _) => digests,
            (None, Some(failure)) => {
                fresh.failed.insert(
                    group.target,
                    WalkFailure {
                        names: group.names,
                        ..failure
                    },
                );
                continue;
            }
            (None, None) => {
                let mut out = HashMap::new();
                match walk_manifest_via_grpc(cs, &group.target, &group.names[0], &mut out).await {
                    Ok(_) => walked += 1,
                    Err(e) => {
                        failed += 1;
                        debug!(image = %group.names[0], error = %format_args!("{e:#}"), "image walk failed");
                        let retry_at = if is_rpc_failure(&e) {
                            Instant::now()
                        } else {
                            Instant::now() + WALK_RETRY_INTERVAL
                        };
                        fresh.failed.insert(
                            group.target,
                            WalkFailure {
                                names: group.names,
                                updated: group.updated,
                                retry_at,
                                absent: is_not_found(&e) || is_unparsable(&e),
                                error: format!("{e:#}"),
                            },
                        );
                        continue;
                    }
                }
                out.into_keys().collect()
            }
        };
        fresh.walks.insert(
            group.target,
            TargetWalk {
                names: group.names,
                updated: group.updated,
                digests,
            },
        );
    }
    let (total, unknown) = (fresh.walks.len(), fresh.failed.len());
    *lock_cache(memo) = fresh;
    debug!(
        walked,
        failed, total, unknown, "containerd image claims refreshed"
    );
    Ok(())
}

/// Who claims `digest` among `walks`: see [`Claim`]. Independent of listing
/// and walk order.
fn claim_of(walks: &BTreeMap<String, TargetWalk>, digest: &str) -> Claim {
    // Claimant key → (repository, its images with their record update time).
    type Images = Vec<(Updated, ClaimedImage)>;
    let mut claimants: BTreeMap<String, (String, Images)> = BTreeMap::new();
    let mut unnamed = false;
    for (target, walk) in walks.iter().filter(|(_, w)| w.digests.contains(digest)) {
        let repos = repositories(&walk.names);
        unnamed |= repos.is_empty();
        let tagged = tag_named(&walk.names);
        for repo in repos {
            let key = if tagged {
                repo.to_string()
            } else {
                format!("{repo}@{target}")
            };
            claimants
                .entry(key)
                .or_insert_with(|| (repo.to_string(), Vec::new()))
                .1
                .push((
                    walk.updated,
                    ClaimedImage {
                        image_ref: best_name(&walk.names).to_string(),
                        target: target.clone(),
                    },
                ));
        }
    }
    match (claimants.len(), unnamed) {
        // A bare image-ID record alone names nothing to serve from.
        (0, _) => Claim::Unclaimed,
        (1, false) => {
            let (_, (repository, mut images)) = claimants.pop_first().expect("one claimant");
            // Tag-named targets first (a claimant never mixes them with a
            // digest-only one), then the newest record.
            images.sort_by(|(a_time, a), (b_time, b)| {
                is_tag_ref(&b.image_ref)
                    .cmp(&is_tag_ref(&a.image_ref))
                    .then_with(|| b_time.cmp(a_time))
                    .then_with(|| a.image_ref.cmp(&b.image_ref))
                    .then_with(|| a.target.cmp(&b.target))
            });
            Claim::One(Claimant {
                repository,
                images: images.into_iter().map(|(_, image)| image).collect(),
            })
        }
        _ => {
            let mut names: Vec<String> = claimants.into_keys().collect();
            if unnamed {
                names.push("<image ID only>".to_string());
            }
            Claim::Ambiguous(names)
        }
    }
}

/// The best registry name among an image's record names: the highest
/// [`ref_name_rank`], then the smallest. `names` is never empty.
fn best_name(names: &[String]) -> &str {
    names
        .iter()
        .max_by(|a, b| {
            ref_name_rank(a)
                .cmp(&ref_name_rank(b))
                .then_with(|| b.cmp(a))
        })
        .expect("a record group has a name")
}

/// Rank an image-record name by its usefulness as a registry reference.
/// Higher is better:
///   3 — tag-form full ref (`host/repo:tag`)
///   2 — digest-form ref (`host/repo@sha256:...` — repo still resolvable)
///   1 — name-only ref (`host/repo`)
///   0 — bare digest / image-ID record (`sha256:<hex>`): containerd's CRI
///       plugin stores one of these for EVERY pulled image, and it is
///       USELESS as a registry ref — parsing it yields repo "sha256"
///       (docker.io-normalized to "library/sha256"), so a daemon built from
///       it fails every blob fetch with UNAUTHORIZED and containers EIO.
fn ref_name_rank(name: &str) -> u8 {
    if name.starts_with("sha256:") || name.starts_with("sha512:") {
        return 0;
    }
    if name.contains('@') {
        return 2;
    }
    // Tag split as in record_matches_ref: the last `:` is a tag separator
    // only when the remainder has no `/` (registry ports are not tags).
    match name.rsplit_once(':') {
        Some((_, tag)) if !tag.is_empty() && !tag.contains('/') => 3,
        _ => 1,
    }
}

/// Group image records by target digest. A group of bare image-ID records
/// (`sha256:...`) only is kept: it still claims its chains, but names no
/// repository, since mapping a chain to a bare digest poisons every consumer
/// downstream (registry backend, auto-accel routing, capture).
fn group_records_by_target(records: &[ImageRecord]) -> Vec<RecordGroup> {
    let mut by_target: BTreeMap<&str, (BTreeSet<&str>, Updated)> = BTreeMap::new();
    for record in records {
        let (names, updated) = by_target.entry(record.target_digest.as_str()).or_default();
        names.insert(record.name.as_str());
        *updated = (*updated).max(record.updated);
    }
    by_target
        .into_iter()
        .map(|(target, (names, updated))| RecordGroup {
            target: target.to_string(),
            names: names.into_iter().map(str::to_string).collect(),
            updated,
        })
        .collect()
}

/// Does an image-record name refer to `image_ref`? Exact match, or the
/// record's name part (before `@digest` / `:tag`) equals a name-only ref.
fn record_matches_ref(record_name: &str, image_ref: &str) -> bool {
    if record_name == image_ref {
        return true;
    }
    if let Some((name, _)) = record_name.split_once('@')
        && name == image_ref
    {
        return true;
    }
    // Tag split: only treat the last `:` as a tag separator when the
    // remainder has no `/` (avoids mangling registry ports like
    // `localhost:5000/img`).
    if let Some((name, tag)) = record_name.rsplit_once(':')
        && !tag.contains('/')
        && name == image_ref
    {
        return true;
    }
    false
}

async fn walk_manifest_via_grpc(
    cs: &ContentStoreClient,
    digest: &str,
    image_ref: &str,
    out: &mut HashMap<String, String>,
) -> Result<bool> {
    let bytes = cs
        .fetch_bytes(digest)
        .await
        .with_context(|| format!("fetch manifest {digest}"))?;
    // Try as index first (multi-arch); if no `manifests` field, treat as
    // manifest. Recursion is bounded by OCI nesting (index → manifest).
    if let Ok(index) = go_json::<OciIndexWithPlatforms>(&bytes)
        && !index.manifests.is_empty()
    {
        let (host, rest) = walkable_children(&index);
        let mut host_results = Vec::with_capacity(host.len());
        for child in host {
            let result = Box::pin(walk_manifest_via_grpc(cs, child, image_ref, out))
                .await
                .map(|_| ());
            if let Err(e) = &result {
                debug!(child = %child, error = %format_args!("{e:#}"), "host-platform child walk failed");
            }
            host_results.push(result);
        }
        let mut rest_resolved = false;
        if walk_rest_children(&host_results, is_not_found) {
            for child in rest {
                match Box::pin(walk_manifest_via_grpc(cs, child, image_ref, out)).await {
                    Ok(registered) => rest_resolved |= registered,
                    Err(e) => {
                        debug!(child = %child, error = %format_args!("{e:#}"), "child walk failed")
                    }
                }
            }
        }
        return index_walk_result(digest, host_results, rest_resolved).map(|()| true);
    }
    let manifest: OciManifest =
        go_json(&bytes).with_context(|| format!("parse manifest {digest}"))?;
    let bootstrap_indices = collect_bootstrap_layers(&manifest, image_ref, out);
    let Some(cfg_desc) = image_config(&manifest) else {
        return Ok(false);
    };
    let cfg_bytes = cs
        .fetch_bytes(&cfg_desc.digest)
        .await
        .with_context(|| format!("fetch image config for {image_ref}"))?;
    let cfg: OciImageConfig =
        go_json(&cfg_bytes).with_context(|| format!("parse image config for {image_ref}"))?;
    if cfg.rootfs.diff_ids.is_empty() {
        return Ok(false);
    }
    register_chain_ids(image_ref, &cfg.rootfs.diff_ids, &bootstrap_indices, out);
    Ok(true)
}

/// The manifest's config descriptor unless the manifest is an OCI artifact. An artifact stored
/// under an image record (an SLSA attestation pulled by digest, say) carries the spec's empty
/// `{}` config and no rootfs, so it has no chainIDs to register. A walk that reaches one returns
/// `Ok(false)`, which an index does not count as a resolved child.
fn image_config(manifest: &OciManifest) -> Option<&OciDescriptor> {
    manifest
        .config
        .as_ref()
        .filter(|c| c.media_type != "application/vnd.oci.empty.v1+json")
}

/// Record bootstrap-annotated layers into the cache map (by layer digest)
/// and return their indices for chainID registration.
fn collect_bootstrap_layers(
    manifest: &OciManifest,
    image_ref: &str,
    out: &mut HashMap<String, String>,
) -> Vec<usize> {
    if manifest.layers.is_empty() && manifest.config.is_none() {
        // Typically an index whose `manifests` failed to parse (e.g. a
        // non-object `platform`) falling through to the manifest parse.
        debug!(image = %image_ref, "manifest has neither layers nor config; nothing to register");
    }
    let mut bootstrap_indices: Vec<usize> = Vec::new();
    for (i, layer) in manifest.layers.iter().enumerate() {
        let is_bootstrap = layer
            .annotations
            .get(NYDUS_BOOTSTRAP_ANNOTATION)
            .map(|s| s == "true")
            .unwrap_or(false);
        if is_bootstrap {
            debug!(
                bootstrap = %layer.digest,
                image = %image_ref,
                media_type = %layer.media_type,
                "discovered nydus bootstrap layer"
            );
            out.insert(layer.digest.clone(), image_ref.to_string());
            bootstrap_indices.push(i);
        }
    }
    bootstrap_indices
}

/// Pure registration step factored out of the walk so unit tests can pin
/// the chainID rules (topmost-for-any-image, bootstrap-layer-for-nydus)
/// without any containerd access.
fn register_chain_ids(
    image_ref: &str,
    diff_ids: &[String],
    bootstrap_indices: &[usize],
    out: &mut HashMap<String, String>,
) {
    let chain_ids = chain_ids(diff_ids);
    // Topmost chain_id makes auto-accel lookup work for STANDARD OCI
    // images on the prepare path — without this entry the chainID-to-
    // image-ref fallback in grpc::prepare misses every Run-of-nginx and
    // both capture and discovery are dead.
    if let Some(top) = chain_ids.last() {
        debug!(
            chain_id = %top,
            image = %image_ref,
            "registered topmost chainID for image"
        );
        out.insert(top.clone(), image_ref.to_string());
    }
    for &i in bootstrap_indices {
        if let Some(chain_id) = chain_ids.get(i) {
            debug!(
                chain_id = %chain_id,
                image = %image_ref,
                layer_index = i,
                "registered chainID for bootstrap layer"
            );
            out.insert(chain_id.clone(), image_ref.to_string());
        }
    }
}

/// Layer + manifest summary used by the auto-accel pipeline. The layer list
/// holds the tar, gzip and zstd layers (skipping nydus-bootstrap / nydus-blob
/// layers, which the auto-accel path doesn't consume) in OCI manifest order,
/// lower → upper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestInfo {
    /// The image's manifest digest (`sha256:...`). The auto-accel sidecar
    /// uses this as the `containerd.io/gc.ref.content.subject` label — an
    /// *outgoing* GC edge that keeps the original manifest (and its layers)
    /// alive while the sidecar exists, because the index blobs read the
    /// original layers from the content store at serve time. The
    /// sidecar's own lifetime is bounded by its synthetic Image record, which
    /// the reconciler deletes once the subject image is gone.
    pub manifest_digest: String,
    /// Layers in device-table order with their on-disk content-store
    /// paths already resolved.
    pub layers: Vec<crate::local_accel::SourceLayer>,
    /// Topmost chainID of the image's rootfs (from the config's diff_ids):
    /// the parent snapshot of every container prepared from this manifest.
    pub chain_id: String,
}

/// An image config's `rootfs.diff_ids`.
fn config_diff_ids(cfg_bytes: &[u8], manifest: &str) -> Result<Vec<String>> {
    let cfg: OciImageConfig =
        go_json(cfg_bytes).with_context(|| format!("parse image config of manifest {manifest}"))?;
    Ok(cfg.rootfs.diff_ids)
}

/// Topmost chainID of an image config's `rootfs.diff_ids`.
#[cfg(test)]
fn top_chain_id(cfg_bytes: &[u8], manifest: &str) -> Result<String> {
    top_chain_of(&config_diff_ids(cfg_bytes, manifest)?, manifest)
}

fn top_chain_of(diff_ids: &[String], manifest: &str) -> Result<String> {
    chain_ids(diff_ids)
        .pop()
        .with_context(|| format!("image config of manifest {manifest} has no diff_ids"))
}

/// The config descriptor digest of a manifest; every image manifest has one.
fn config_digest<'a>(manifest: &'a OciManifest, digest: &str) -> Result<&'a str> {
    manifest
        .config
        .as_ref()
        .map(|c| c.digest.as_str())
        .with_context(|| format!("manifest {digest} has no config"))
}

/// Resolve an index/manifest digest to (manifest_digest, gzip_layers) for
/// the current host's architecture, reading blobs via gRPC. For a
/// single-manifest digest this is a pass-through; for a multi-arch index
/// we pick the matching child by GOARCH.
async fn resolve_accel_layers_via_grpc(
    cs: &ContentStoreClient,
    digest: &str,
    content_root: &std::path::Path,
) -> Result<ManifestInfo> {
    // The digest is the image record's target or the host child picked
    // from it, never speculative, so a miss is worth a warning; "no host
    // match" and "no data layers" are normal for many images and stay at
    // the caller's debug.
    let bytes = cs
        .fetch_bytes(digest)
        .await
        .with_context(|| format!("fetch manifest {digest}"))
        .inspect_err(|e| {
            if !is_rpc_failure(e) {
                warn!(
                    manifest = %digest,
                    error = %format_args!("{e:#}"),
                    "image manifest not in content store; auto-accel falls back to overlay"
                );
            }
        })?;
    if let Ok(index) = go_json::<OciIndexWithPlatforms>(&bytes)
        && !index.manifests.is_empty()
    {
        let child = pick_host_arch_child(&index)
            .with_context(|| format!("no manifest in index {digest} matches this host"))?;
        return Box::pin(resolve_accel_layers_via_grpc(cs, &child, content_root)).await;
    }
    let manifest: OciManifest =
        go_json(&bytes).with_context(|| format!("parse manifest {digest}"))?;
    let config = config_digest(&manifest, digest)?;
    let cfg_bytes = cs
        .fetch_bytes(config)
        .await
        .with_context(|| format!("fetch image config {config}"))?;
    let diff_ids = config_diff_ids(&cfg_bytes, digest)?;
    Ok(ManifestInfo {
        manifest_digest: digest.to_string(),
        layers: accel_layers_from_manifest(&manifest, digest, content_root, &diff_ids)?,
        chain_id: top_chain_of(&diff_ids, digest)?,
    })
}

/// Pick the index child matching the host architecture/OS. Pure so tests
/// can pin the GOARCH translation.
fn pick_host_arch_child(index: &OciIndexWithPlatforms) -> Option<String> {
    index
        .manifests
        .iter()
        .find(|child| is_host_platform(child))
        .map(|child| child.digest.clone())
}

/// Index children for the chainID map, split into `(host, rest)`: the
/// children matching the host architecture/OS (variants such as arm64/v8
/// and `os.features` all match), then every other child in index order.
/// containerd by default pulls only the host-platform child, so the rest
/// (foreign arches, `unknown/unknown` attestation manifests) are usually
/// absent and are walked only when `walk_rest_children` says so. That
/// fallback keeps indices without platform info, and images pulled for a
/// foreign platform (`--platform`, tarball import), resolvable.
fn walkable_children(index: &OciIndexWithPlatforms) -> (Vec<&str>, Vec<&str>) {
    let (mut host, mut rest) = (Vec::new(), Vec::new());
    for child in &index.manifests {
        let group = if is_host_platform(child) {
            &mut host
        } else {
            &mut rest
        };
        group.push(child.digest.as_str());
    }
    (host, rest)
}

/// Whether to walk the non-host children: only when no host child
/// resolved and every host failure is a miss (`is_miss`), so a transport
/// error or a broken host manifest never fans out to every foreign child.
/// True for an index with no host child.
fn walk_rest_children(
    host_results: &[Result<()>],
    is_miss: impl Fn(&anyhow::Error) -> bool,
) -> bool {
    host_results.iter().all(|r| r.as_ref().is_err_and(&is_miss))
}

/// Outcome of an index walk: Ok when any child resolved, otherwise one
/// error for the caller to log, preferring a host failure that is not a
/// plain miss because it says more.
fn index_walk_result(
    digest: &str,
    host_results: Vec<Result<()>>,
    rest_resolved: bool,
) -> Result<()> {
    if rest_resolved || host_results.iter().any(Result::is_ok) {
        return Ok(());
    }
    let mut errors: Vec<anyhow::Error> = host_results.into_iter().filter_map(Result::err).collect();
    if errors.is_empty() {
        bail!("no child manifest of index {digest} is in the content store");
    }
    let e = errors.swap_remove(errors.iter().position(|e| !is_not_found(e)).unwrap_or(0));
    if is_not_found(&e) {
        Err(e.context(format!(
            "host-platform manifest or config of index {digest} not in content store; \
             pull in flight or content missing"
        )))
    } else {
        Err(e.context(format!(
            "host-platform manifest of index {digest} unreadable"
        )))
    }
}

fn is_host_platform(child: &OciIndexEntry) -> bool {
    child.platform.as_ref().is_some_and(|p| {
        p.architecture == registry_client::host_go_arch() && p.os == std::env::consts::OS
    })
}

/// Whether a layer of this media type can be referenced in place: uncompressed, gzip or zstd
/// tar, in OCI (`tar+gzip`) or Docker (`tar.gzip`) spelling.
fn is_referenceable_layer(media_type: &str) -> bool {
    ["tar", "tar+gzip", "tar.gzip", "tar+zstd", "tar.zstd"]
        .iter()
        .any(|suffix| {
            media_type
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.'))
        })
}

/// A manifest's layers that are absent from the content store. containerd skips fetching
/// a layer whose snapshot already exists, so a layer whose blob was garbage-collected while its
/// snapshot lived on stays missing after later pulls; the auto-accel worker backfills them.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("manifest {manifest}: layer blobs not in the content store: {}", digests.join(", "))]
pub struct MissingLayers {
    pub manifest: String,
    pub digests: Vec<String>,
}

/// A manifest's layers as the auto-accel path converts them, each with the
/// diff ID its config lists at its index and its on-disk content-store path.
/// Every layer must be a tar, gzip or zstd layer with a diff ID: the artifact
/// stands for the chain those diff IDs make, so none may be left out. Pure
/// (filesystem check aside) and shared by the gRPC and CLI paths. Absent blobs
/// fail with [`MissingLayers`], naming all of them.
fn accel_layers_from_manifest(
    manifest: &OciManifest,
    digest: &str,
    content_root: &std::path::Path,
    diff_ids: &[String],
) -> Result<Vec<crate::local_accel::SourceLayer>> {
    if manifest.layers.len() != diff_ids.len() {
        bail!(
            "manifest {digest} has {} layers but its config {} diff IDs",
            manifest.layers.len(),
            diff_ids.len()
        );
    }
    let mut layers = Vec::with_capacity(manifest.layers.len());
    let mut missing = Vec::new();
    for (layer, diff_id) in manifest.layers.iter().zip(diff_ids) {
        let is_nydus = layer
            .annotations
            .get(NYDUS_BOOTSTRAP_ANNOTATION)
            .is_some_and(|s| s == "true")
            || layer.media_type.contains("nydus");
        if is_nydus {
            bail!(
                "layer {} is a nydus layer; node-local acceleration converts OCI images",
                layer.digest
            );
        }
        // Layers are referenced in place: gzip through zran, zstd through frame-aligned
        // contexts, uncompressed tar directly. Checked before the blob lookup so any other
        // encoding reports why the image is not a candidate instead of failing inside the
        // converter on an unparsable tar header.
        if !is_referenceable_layer(&layer.media_type) {
            bail!(
                "layer {} is {}; node-local acceleration needs tar, gzip or zstd layers",
                layer.digest,
                layer.media_type
            );
        }
        let hex = layer
            .digest
            .strip_prefix("sha256:")
            .unwrap_or(&layer.digest);
        let path = content_root.join("blobs").join("sha256").join(hex);
        if !path.is_file() {
            missing.push(layer.digest.clone());
            continue;
        }
        layers.push(crate::local_accel::SourceLayer {
            digest: layer.digest.clone(),
            diff_id: diff_id.clone(),
            path,
        });
    }
    if !missing.is_empty() {
        return Err(MissingLayers {
            manifest: digest.to_string(),
            digests: missing,
        }
        .into());
    }
    if layers.is_empty() {
        bail!("manifest {digest} has no data layers");
    }
    Ok(layers)
}

#[derive(Deserialize)]
struct OciIndexWithPlatforms {
    #[serde(default)]
    manifests: Vec<OciIndexEntry>,
}

#[derive(Deserialize)]
struct OciIndexEntry {
    digest: String,
    #[serde(default)]
    platform: Option<OciPlatform>,
}

#[derive(Deserialize)]
struct OciPlatform {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
}

/// Compute the containerd snapshot chainID list from an ordered list of
/// diff_ids. `chain[0] = diff_ids[0]`; `chain[i] = sha256(chain[i-1] + " " + diff_ids[i])`.
fn chain_ids(diff_ids: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(diff_ids.len());
    for (i, d) in diff_ids.iter().enumerate() {
        if i == 0 {
            out.push(d.clone());
        } else {
            let prev = &out[i - 1];
            let combined = format!("{} {}", prev, d);
            let hash = Sha256::digest(combined.as_bytes());
            out.push(format!("sha256:{}", hex_lower(hash.as_ref())));
        }
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("write to String cannot fail");
    }
    out
}

// ---------------------------------------------------------------------------
// Legacy CLI fallback (no gRPC client wired). Each helper spawns crictl/ctr
// subprocesses — callers run these via `blocking::unblock` only.
// ---------------------------------------------------------------------------

fn manifest_info_via_cli(image_ref: &str, content_root: &std::path::Path) -> Result<ManifestInfo> {
    let out = run_first_ok(&[
        &["crictl", "images", "-o", "json"],
        &["k3s", "crictl", "images", "-o", "json"],
    ])?;
    let parsed: CrictlImages = serde_json::from_slice(&out)?;
    for img in parsed.images {
        // Match either a repoTag (`name:tag`) or a repoDigest's name part
        // (`name@sha256:...`). The caller usually has the ref in tag form.
        let mut matched_manifest: Option<String> = None;
        for repo_digest in &img.repo_digests {
            if let Some((name, manifest_digest)) = repo_digest.split_once('@')
                && (name == image_ref || img.repo_tags.iter().any(|t| t == image_ref))
            {
                matched_manifest = Some(manifest_digest.to_string());
                break;
            }
        }
        let Some(manifest_digest) = matched_manifest else {
            continue;
        };
        return resolve_accel_layers_via_cli(&manifest_digest, content_root);
    }
    bail!(
        "image {image_ref} not found in crictl images output; \
         make sure it's been pulled at least once"
    )
}

fn resolve_accel_layers_via_cli(
    digest: &str,
    content_root: &std::path::Path,
) -> Result<ManifestInfo> {
    let bytes = run_first_ok(&[
        &["ctr", "-n", "k8s.io", "content", "get", digest],
        &["k3s", "ctr", "-n", "k8s.io", "content", "get", digest],
    ])?;
    if let Ok(index) = go_json::<OciIndexWithPlatforms>(&bytes)
        && !index.manifests.is_empty()
    {
        let child = pick_host_arch_child(&index)
            .with_context(|| format!("no manifest in index {digest} matches this host"))?;
        return resolve_accel_layers_via_cli(&child, content_root);
    }
    let manifest: OciManifest =
        go_json(&bytes).with_context(|| format!("parse manifest {digest}"))?;
    let config = config_digest(&manifest, digest)?;
    let cfg_bytes = run_first_ok(&[
        &["ctr", "-n", "k8s.io", "content", "get", config],
        &["k3s", "ctr", "-n", "k8s.io", "content", "get", config],
    ])
    .with_context(|| format!("fetch image config {config}"))?;
    let diff_ids = config_diff_ids(&cfg_bytes, digest)?;
    Ok(ManifestInfo {
        manifest_digest: digest.to_string(),
        layers: accel_layers_from_manifest(&manifest, digest, content_root, &diff_ids)?,
        chain_id: top_chain_of(&diff_ids, digest)?,
    })
}

/// Run the first command whose binary exists & exits successfully.
fn run_first_ok(candidates: &[&[&str]]) -> Result<Vec<u8>> {
    let mut last_err: Option<String> = None;
    for argv in candidates {
        let Some((prog, args)) = argv.split_first() else {
            continue;
        };
        match Command::new(prog).args(args).output() {
            Ok(o) if o.status.success() => return Ok(o.stdout),
            Ok(o) => {
                last_err = Some(format!(
                    "{} {:?} exited {}: {}",
                    prog,
                    args,
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                ));
            }
            Err(e) => {
                last_err = Some(format!("{prog} {args:?}: {e}"));
            }
        }
    }
    match last_err {
        Some(e) => {
            warn!(error = %e, "all containerd CLI candidates failed");
            bail!("all containerd CLI candidates failed: {e}")
        }
        None => bail!("no containerd CLI candidates provided"),
    }
}

#[cfg(test)]
impl ContainerdLookup {
    /// Put a walked target into `namespace`'s memo, as a listing would.
    pub(crate) fn seed(
        &self,
        namespace: &str,
        target: &str,
        names: &[&str],
        updated: i64,
        digests: &[&str],
    ) {
        lock_cache(&self.namespace(namespace).memo).walks.insert(
            target.to_string(),
            TargetWalk {
                names: names.iter().map(|n| n.to_string()).collect(),
                updated: (updated, 0),
                digests: digests.iter().map(|d| d.to_string()).collect(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accel_layers_reject_other_encodings_before_reading_blobs() {
        let manifest: OciManifest = serde_json::from_value(serde_json::json!({ "layers": [
            { "digest": "sha256:aa", "mediaType": "application/vnd.oci.image.layer.v1.tar+bzip2" },
        ]}))
        .unwrap();
        // The content root does not exist: the media type must be rejected first.
        let err = accel_layers_from_manifest(
            &manifest,
            "sha256:m",
            std::path::Path::new("/nonexistent"),
            &diff_ids(1),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("tar+bzip2") && err.contains("needs tar"),
            "{err}"
        );
    }

    fn diff_ids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("sha256:d{i}")).collect()
    }

    /// Each layer carries the diff ID at its index, and an image whose layers
    /// and diff IDs do not pair up, or that holds a nydus layer, is no
    /// candidate.
    #[test]
    fn accel_layers_carry_their_diff_ids() {
        let root = tempfile::tempdir().unwrap();
        let blobs = root.path().join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(blobs.join("aa"), b"a").unwrap();
        std::fs::write(blobs.join("bb"), b"b").unwrap();
        let gzip = "application/vnd.oci.image.layer.v1.tar+gzip";
        let manifest: OciManifest = serde_json::from_value(serde_json::json!({ "layers": [
            { "digest": "sha256:aa", "mediaType": gzip },
            { "digest": "sha256:bb", "mediaType": "application/vnd.oci.image.layer.v1.tar" },
        ]}))
        .unwrap();
        let layers =
            accel_layers_from_manifest(&manifest, "sha256:m", root.path(), &diff_ids(2)).unwrap();
        assert_eq!(
            layers
                .iter()
                .map(|l| l.diff_id.as_str())
                .collect::<Vec<_>>(),
            ["sha256:d0", "sha256:d1"]
        );
        for n in [1, 3] {
            let err = accel_layers_from_manifest(&manifest, "sha256:m", root.path(), &diff_ids(n))
                .unwrap_err();
            assert!(format!("{err:#}").contains("diff IDs"), "{err:#}");
        }
        let nydus: OciManifest = serde_json::from_value(serde_json::json!({ "layers": [
            { "digest": "sha256:aa", "mediaType": gzip },
            { "digest": "sha256:bb", "mediaType": gzip,
              "annotations": { NYDUS_BOOTSTRAP_ANNOTATION: "true" } },
        ]}))
        .unwrap();
        let err =
            accel_layers_from_manifest(&nydus, "sha256:m", root.path(), &diff_ids(2)).unwrap_err();
        assert!(format!("{err:#}").contains("nydus layer"), "{err:#}");
    }

    /// Image JSON reads as containerd's Go decoder reads it: the last of
    /// duplicate keys wins, `null` leaves a field at its default, and invalid
    /// UTF-8 is no error; JSON it rejects is [`Unparsable`].
    #[test]
    fn image_json_is_read_like_go() {
        let json = [
            &br#"{"layers":[{"digest":"sha256:a"}],"config":null,"layers":[{"digest":"sha256:b","annotations":{"k":""#[..],
            &[0xff],
            br#""}}]}"#,
        ]
        .concat();
        let manifest: OciManifest = go_json(&json).unwrap();
        assert_eq!(
            manifest
                .layers
                .iter()
                .map(|l| l.digest.as_str())
                .collect::<Vec<_>>(),
            ["sha256:b"]
        );
        assert!(manifest.config.is_none());
        let config: OciImageConfig = go_json(
            br#"{"rootfs":{"diff_ids":["sha256:first"]},"rootfs":{"diff_ids":["sha256:last"]}}"#,
        )
        .unwrap();
        assert_eq!(config.rootfs.diff_ids, ["sha256:last"]);
        for broken in [&br#"{"rootfs":"#[..], br#"{"layers":"many"}"#] {
            let err = go_json::<OciManifest>(broken).err().unwrap();
            assert!(is_unparsable(&err.context("walk")));
        }
    }

    #[test]
    fn referenceable_layer_media_types() {
        for media_type in [
            "application/vnd.oci.image.layer.v1.tar",
            "application/vnd.oci.image.layer.v1.tar+gzip",
            "application/vnd.oci.image.layer.v1.tar+zstd",
            "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
            "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "application/vnd.docker.image.rootfs.diff.tar.zstd",
        ] {
            assert!(is_referenceable_layer(media_type), "{media_type}");
        }
        for media_type in [
            "application/vnd.oci.image.layer.v1.tar+bzip2",
            "application/vnd.oci.image.config.v1+json",
            "application/octet-stream",
        ] {
            assert!(!is_referenceable_layer(media_type), "{media_type}");
        }
    }

    #[test]
    fn gzip_layers_name_every_missing_blob() {
        let root = tempfile::tempdir().unwrap();
        let blobs = root.path().join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(blobs.join("bb"), b"present").unwrap();
        let gzip = "application/vnd.oci.image.layer.v1.tar+gzip";
        let manifest: OciManifest = serde_json::from_value(serde_json::json!({ "layers": [
            { "digest": "sha256:aa", "mediaType": gzip },
            { "digest": "sha256:bb", "mediaType": gzip },
            { "digest": "sha256:cc", "mediaType": gzip },
        ]}))
        .unwrap();
        let err = accel_layers_from_manifest(&manifest, "sha256:m", root.path(), &diff_ids(3))
            .unwrap_err();
        // Downcastable through the context callers attach.
        let err = err.context("resolve manifest");
        assert_eq!(
            err.downcast_ref::<MissingLayers>(),
            Some(&MissingLayers {
                manifest: "sha256:m".to_string(),
                digests: vec!["sha256:aa".to_string(), "sha256:cc".to_string()],
            })
        );
    }

    fn index_from_json(json: serde_json::Value) -> OciIndexWithPlatforms {
        serde_json::from_value(json).expect("valid index JSON")
    }

    fn entry(digest: &str, arch: &str, os: &str) -> serde_json::Value {
        serde_json::json!({
            "digest": digest,
            "platform": { "architecture": arch, "os": os }
        })
    }

    /// A multi-arch index lists foreign arches and attestation manifests
    /// that containerd by default does not pull; the host child is walked
    /// first and the rest only as a fallback.
    #[test]
    fn walkable_children_puts_host_platform_first() {
        let host = registry_client::host_go_arch();
        let os = std::env::consts::OS;
        let foreign = if host == "amd64" { "s390x" } else { "amd64" };
        let index = index_from_json(serde_json::json!({ "manifests": [
            entry("sha256:foreign", foreign, os),
            entry("sha256:host", host, os),
            entry("sha256:ppc", "ppc64le", os),
            entry("sha256:attest-host", "unknown", "unknown"),
            entry("sha256:attest-foreign", "unknown", "unknown"),
            entry("sha256:other-os", host, "windows"),
        ]}));
        let (host_children, rest) = walkable_children(&index);
        assert_eq!(host_children, vec!["sha256:host"]);
        assert_eq!(
            rest,
            vec![
                "sha256:foreign",
                "sha256:ppc",
                "sha256:attest-host",
                "sha256:attest-foreign",
                "sha256:other-os",
            ]
        );
        assert_eq!(pick_host_arch_child(&index).as_deref(), Some("sha256:host"));
    }

    /// Variants (arm64/v8 vs bare arm64) and `os.features` (the nydus
    /// sibling of a dual-image index) all match the host, so no child that
    /// could be the host's manifest or its nydus bootstrap is demoted.
    #[test]
    fn walkable_children_keeps_every_host_variant() {
        let host = registry_client::host_go_arch();
        let os = std::env::consts::OS;
        let index = index_from_json(serde_json::json!({ "manifests": [
            entry("sha256:bare", host, os),
            { "digest": "sha256:v8",
              "platform": { "architecture": host, "os": os, "variant": "v8" } },
            { "digest": "sha256:nydus",
              "platform": { "architecture": host, "os": os,
                            "os.features": ["nydus.remoteimage.v1"] } },
            entry("sha256:foreign", "riscv-none", os),
        ]}));
        let (host_children, rest) = walkable_children(&index);
        assert_eq!(
            host_children,
            vec!["sha256:bare", "sha256:v8", "sha256:nydus"]
        );
        assert_eq!(rest, vec!["sha256:foreign"]);
    }

    /// Without platform info (or with no host match) every child is in the
    /// fallback set, and the fallback is always walked.
    #[test]
    fn walkable_children_falls_back_to_all_without_host_match() {
        let index = index_from_json(serde_json::json!({ "manifests": [
            { "digest": "sha256:a" },
            { "digest": "sha256:b", "platform": {} },
            entry("sha256:c", "riscv-none", "plan9"),
        ]}));
        let (host_children, rest) = walkable_children(&index);
        assert!(host_children.is_empty());
        assert_eq!(rest, vec!["sha256:a", "sha256:b", "sha256:c"]);
        assert!(walk_rest_children(&[], is_not_found));
        assert_eq!(pick_host_arch_child(&index), None);
    }

    fn not_found(digest: &str) -> Result<()> {
        Err(anyhow::Error::new(tonic::Status::not_found("gone"))
            .context(format!("fetch manifest {digest}")))
    }

    /// An image pulled for a foreign platform (`ctr pull --platform`, a
    /// foreign tarball import, binfmt emulation) has its own child locally
    /// but not the host child: the host child's NotFound falls through to
    /// the rest, and the foreign child resolving makes the index resolve.
    #[test]
    fn walkable_children_walks_foreign_child_when_host_child_missing() {
        let host = registry_client::host_go_arch();
        let os = std::env::consts::OS;
        let foreign = if host == "amd64" { "arm64" } else { "amd64" };
        let index = index_from_json(serde_json::json!({ "manifests": [
            entry("sha256:foreign", foreign, os),
            entry("sha256:host", host, os),
        ]}));
        let (host_children, rest) = walkable_children(&index);
        assert_eq!(host_children, vec!["sha256:host"]);
        assert_eq!(rest, vec!["sha256:foreign"]);

        assert!(walk_rest_children(
            &[not_found("sha256:host")],
            is_not_found
        ));
        assert!(index_walk_result("sha256:idx", vec![not_found("sha256:host")], true).is_ok());
    }

    /// The fallback never runs when a host child resolved or failed for a
    /// reason other than absence, and an index nothing resolved for is an
    /// error the refresh logs once, naming the expected cause.
    #[test]
    fn index_walk_stays_on_host_unless_every_host_child_is_missing() {
        let down = || Err(anyhow::Error::new(tonic::Status::unavailable("down")));
        assert!(!walk_rest_children(
            &[not_found("sha256:a"), Ok(())],
            is_not_found
        ));
        assert!(!walk_rest_children(&[down()], is_not_found));
        assert!(
            index_walk_result("sha256:idx", vec![not_found("sha256:a"), Ok(())], false).is_ok()
        );

        let err = index_walk_result("sha256:idx", vec![not_found("sha256:a")], false).unwrap_err();
        assert!(
            format!("{err:#}").contains("pull in flight or content missing"),
            "{err:#}"
        );
        assert!(is_not_found(&err));

        let err = index_walk_result("sha256:idx", vec![not_found("sha256:a"), down()], false)
            .unwrap_err();
        assert!(
            !is_not_found(&err),
            "the non-miss failure is reported: {err:#}"
        );

        let err = index_walk_result("sha256:idx", vec![], false).unwrap_err();
        assert!(err.to_string().contains("sha256:idx"), "{err}");
    }

    const NS: &str = "k8s.io";

    /// A lookup seeded in [`NS`] with `(target, record names, claimed
    /// digests)` walks, updated in the given order.
    fn seeded(walks: &[(&str, &[&str], &[&str])]) -> ContainerdLookup {
        let lookup = ContainerdLookup::new_cli_only();
        for (i, (target, names, digests)) in walks.iter().enumerate() {
            lookup.seed(NS, target, names, i as i64, digests);
        }
        lookup
    }

    fn one(repository: &str, images: &[(&str, &str)]) -> Claim {
        Claim::One(Claimant {
            repository: repository.to_string(),
            images: images
                .iter()
                .map(|(image_ref, target)| ClaimedImage {
                    image_ref: image_ref.to_string(),
                    target: target.to_string(),
                })
                .collect(),
        })
    }

    #[test]
    fn one_image_claiming_a_chain_is_named() {
        let lookup = seeded(&[
            ("sha256:tx", &["reg/app:v1"], &["sha256:x"]),
            ("sha256:ty", &["reg/other:latest"], &["sha256:y"]),
        ]);
        let claim = lookup.lookup_cached(NS, "sha256:x").unwrap();
        assert_eq!(claim, one("reg/app", &[("reg/app:v1", "sha256:tx")]));
        assert_eq!(
            lookup.lookup_cached(NS, "sha256:z").unwrap(),
            Claim::Unclaimed
        );
        // Claims are per namespace.
        assert_eq!(
            lookup.lookup_cached("default", "sha256:x").unwrap(),
            Claim::Unclaimed
        );
    }

    /// A bare image-ID record still claims its chain: alone it names nothing,
    /// next to a named image it makes the chain ambiguous.
    #[test]
    fn image_id_records_claim_but_are_never_named() {
        let id = "sha256:0c0da3558734bbf673448b752bb6c139cbd3ece8060c6589370280b8ba631d9e";
        let alone = seeded(&[("sha256:t1", &[id], &["sha256:x"])]);
        assert_eq!(
            alone.lookup_cached(NS, "sha256:x").unwrap(),
            Claim::Unclaimed
        );
        let shared = seeded(&[
            ("sha256:t1", &[id], &["sha256:x"]),
            ("sha256:t2", &["reg/claimant-b:1"], &["sha256:x"]),
        ]);
        assert!(matches!(
            shared.lookup_cached(NS, "sha256:x").unwrap(),
            Claim::Ambiguous(_)
        ));
        // The ID record of a named image is just another name of its target.
        let named = seeded(&[("sha256:t1", &[id, "reg/app:1"], &["sha256:x"])]);
        assert_eq!(
            named.lookup_cached(NS, "sha256:x").unwrap(),
            one("reg/app", &[("reg/app:1", "sha256:t1")])
        );
    }

    /// A target named from two repositories (one record of each pointing at
    /// the same manifest) is two claimants, whatever names rank first.
    #[test]
    fn one_target_named_from_two_repositories_is_ambiguous() {
        let lookup = seeded(&[(
            "sha256:m",
            &[
                "reg/app:1",
                "reg/app@sha256:m",
                "other.example/claimant-b:1",
            ],
            &["sha256:x"],
        )]);
        assert_eq!(
            lookup.lookup_cached(NS, "sha256:x").unwrap(),
            Claim::Ambiguous(vec![
                "other.example/claimant-b".to_string(),
                "reg/app".to_string()
            ])
        );
    }

    /// The tag-named targets of one repository (a rebuild with the same
    /// layers, an index and a manifest tagged apart) are one claimant; its
    /// images are ordered newest record first, then by name.
    #[test]
    fn tagged_targets_of_one_repository_are_one_claimant() {
        let lookup = seeded(&[
            ("sha256:index", &["reg/app:1"], &["sha256:x"]),
            (
                "sha256:manifest",
                &["reg/app:arch", "reg/app@sha256:manifest"],
                &["sha256:x"],
            ),
            ("sha256:rebuild", &["reg/app:2"], &["sha256:x"]),
        ]);
        let claim = lookup.lookup_cached(NS, "sha256:x").unwrap();
        assert_eq!(
            claim,
            one(
                "reg/app",
                &[
                    ("reg/app:2", "sha256:rebuild"),
                    ("reg/app:arch", "sha256:manifest"),
                    ("reg/app:1", "sha256:index"),
                ]
            )
        );
        let Claim::One(claimant) = claim else {
            unreachable!()
        };
        assert_eq!(claimant.image_ref(), "reg/app:2");
        assert!(claimant.admits("reg/app@sha256:abc"));
        assert!(!claimant.admits("reg/app2:1"));
        assert!(!claimant.admits("sha256:abc"));
    }

    /// A target only digest records name is a claimant of its own, whatever
    /// repository the records name and however recent they are: alone it is
    /// the claimant, next to a tag claimant of the same repository the chain is
    /// ambiguous.
    #[test]
    fn a_digest_only_target_is_its_own_claimant() {
        let alone = seeded(&[("sha256:pinned", &["reg/app@sha256:pinned"], &["sha256:x"])]);
        assert_eq!(
            alone.lookup_cached(NS, "sha256:x").unwrap(),
            one("reg/app", &[("reg/app@sha256:pinned", "sha256:pinned")])
        );
        let lookup = seeded(&[
            ("sha256:tagged", &["reg/app:1"], &["sha256:x"]),
            ("sha256:pinned", &["reg/app@sha256:pinned"], &["sha256:x"]),
        ]);
        assert_eq!(
            lookup.lookup_cached(NS, "sha256:x").unwrap(),
            Claim::Ambiguous(vec![
                "reg/app".to_string(),
                "reg/app@sha256:pinned".to_string()
            ])
        );
        // Two digest-only targets are two claimants.
        let two = seeded(&[
            ("sha256:a", &["reg/app@sha256:a"], &["sha256:x"]),
            ("sha256:b", &["reg/app@sha256:b"], &["sha256:x"]),
        ]);
        assert!(matches!(
            two.lookup_cached(NS, "sha256:x").unwrap(),
            Claim::Ambiguous(_)
        ));
    }

    /// A target whose walk failed might claim anything: it makes a sole
    /// claimant uncertain unless it is tag-named in that claimant's
    /// repository, and never shrinks the claimant set.
    #[test]
    fn an_unwalked_target_makes_other_repositories_claims_uncertain() {
        let lookup = seeded(&[("sha256:t", &["reg/app:1"], &["sha256:x"])]);
        let fail_as = |names: &[&str], absent: bool| {
            lock_cache(&lookup.namespace(NS).memo).failed.insert(
                "sha256:broken".to_string(),
                WalkFailure {
                    names: names.iter().map(|n| n.to_string()).collect(),
                    updated: (0, 0),
                    retry_at: Instant::now(),
                    absent,
                    error: "unreadable".to_string(),
                },
            );
        };
        let fail = |names: &[&str]| fail_as(names, false);
        fail(&["reg/app:2"]);
        assert!(matches!(
            lookup.lookup_cached(NS, "sha256:x").unwrap(),
            Claim::One(_)
        ));
        // What the walked targets claim stays known.
        assert!(matches!(
            lookup.lookup_walked(NS, "sha256:x"),
            Claim::One(_)
        ));
        for names in [
            &["other.example/b:1"][..],
            &["reg/app@sha256:broken"],
            &["reg/app:2", "other.example/b:1"],
            &["sha256:0c0da3558734bbf673448b752bb6c139cbd3ece8060c6589370280b8ba631d9e"],
        ] {
            fail(names);
            let err = lookup.lookup_cached(NS, "sha256:x").unwrap_err();
            assert!(format!("{err:#}").contains("sha256:broken"), "{err:#}");
        }
        // A target whose content is absent can be the image of no container.
        fail_as(&["other.example/b:1"], true);
        assert!(matches!(
            lookup.lookup_cached(NS, "sha256:x").unwrap(),
            Claim::One(_)
        ));
        // Claims that serve nothing anyway are unaffected.
        assert_eq!(
            lookup.lookup_cached(NS, "sha256:y").unwrap(),
            Claim::Unclaimed
        );
    }

    /// Lookups that arrive while a listing is pending share its outcome,
    /// failure included, instead of listing once each.
    #[test]
    fn waiters_share_a_failed_listing() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::config::ContainerdConfig {
            address: Some(dir.path().join("absent.sock")),
            namespace: NS.to_string(),
            content_root: Some(dir.path().to_path_buf()),
            hosts_dir: None,
        };
        let lookup = ContainerdLookup::new(ContentStoreClient::new(&config).unwrap());
        let state = lookup.namespace(NS);
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let gate = state.gate.lock().await;
            let waiters =
                futures::future::join_all((0..8).map(|_| Box::pin(lookup.lookup(NS, "sha256:x"))));
            let release = async {
                compio::time::sleep(Duration::from_millis(20)).await;
                drop(gate);
            };
            let (results, ()) = futures::future::join(waiters, release).await;
            assert!(results.iter().all(Result::is_err));
        });
        assert_eq!(state.started.load(Ordering::SeqCst), 1);
        // A lookup arriving after that listing finished lists again.
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(lookup.lookup(NS, "sha256:x"))
            .unwrap_err();
        assert_eq!(state.started.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn namespace_comes_from_the_snapshot_key() {
        assert_eq!(namespace_of_key("k8s.io/12/sha256:abc"), Some("k8s.io"));
        assert_eq!(namespace_of_key("moby/3/container-id"), Some("moby"));
        assert_eq!(namespace_of_key("sha256:abc"), None);
        assert_eq!(namespace_of_key("a/b"), None);
        assert_eq!(namespace_of_key("/1/x"), None);
    }

    #[test]
    fn top_chain_id_is_the_last_chain_id_of_the_config() {
        let diff_ids = ["sha256:aa".to_string(), "sha256:bb".to_string()];
        let cfg = serde_json::json!({"rootfs": {"type": "layers", "diff_ids": diff_ids}});
        let top = top_chain_id(&serde_json::to_vec(&cfg).unwrap(), "sha256:m").unwrap();
        assert_eq!(Some(&top), chain_ids(&diff_ids).last());

        let empty = serde_json::json!({"rootfs": {"type": "layers", "diff_ids": []}});
        assert!(top_chain_id(&serde_json::to_vec(&empty).unwrap(), "sha256:m").is_err());
    }

    /// chainID computation is the contract with containerd's snapshot
    /// naming. `chain[0] = diff[0]`, `chain[i] = sha256(chain[i-1] + " " +
    /// diff[i])` — pin with a known-good vector.
    #[test]
    fn chain_ids_match_containerd_algorithm() {
        let diff_ids = vec![
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ];
        let chains = chain_ids(&diff_ids);
        assert_eq!(chains[0], diff_ids[0]);
        // sha256("sha256:aaa... sha256:bbb...") — computed once, pinned.
        let combined = format!("{} {}", diff_ids[0], diff_ids[1]);
        let expected = format!(
            "sha256:{}",
            hex_lower(Sha256::digest(combined.as_bytes()).as_ref())
        );
        assert_eq!(chains[1], expected);
    }

    #[test]
    fn register_chain_ids_registers_topmost_for_plain_images() {
        let mut out = HashMap::new();
        let diff_ids = vec!["sha256:layer0".to_string(), "sha256:layer1".to_string()];
        register_chain_ids("docker.io/library/nginx:1.27", &diff_ids, &[], &mut out);
        let chains = chain_ids(&diff_ids);
        assert_eq!(
            out.get(chains.last().unwrap()).map(String::as_str),
            Some("docker.io/library/nginx:1.27")
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn register_chain_ids_registers_bootstrap_layers() {
        let mut out = HashMap::new();
        let diff_ids = vec!["sha256:layer0".to_string(), "sha256:layer1".to_string()];
        register_chain_ids("reg/nydus:tag", &diff_ids, &[1], &mut out);
        let chains = chain_ids(&diff_ids);
        assert!(out.contains_key(&chains[1]));
        assert!(out.contains_key(chains.last().unwrap()));
    }

    /// A config without `rootfs` (a bare `{}` under an image config media type) parses with no
    /// diff_ids instead of failing the walk; resolving a chainID from it still fails.
    #[test]
    fn config_without_rootfs_has_no_diff_ids() {
        let cfg: OciImageConfig = serde_json::from_slice(b"{}").unwrap();
        assert!(cfg.rootfs.diff_ids.is_empty());
        let err = top_chain_id(b"{}", "sha256:m").unwrap_err();
        assert!(format!("{err:#}").contains("has no diff_ids"), "{err:#}");
    }

    /// An attestation manifest (empty `{}` config, DSSE layer) is skipped instead of failing the
    /// walk with "parse image config"; any other config, whatever its media type, is walked.
    #[test]
    fn image_config_skips_artifact_manifests() {
        let parse = |v: serde_json::Value| serde_json::from_value::<OciManifest>(v).unwrap();
        let attestation = parse(serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.oci.image.config.v1+json",
            "config": { "mediaType": "application/vnd.oci.empty.v1+json",
                        "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                        "size": 2, "data": "e30=" },
            "layers": [{ "mediaType": "application/vnd.dsse.envelope.v1+json",
                         "digest": "sha256:dsse", "size": 9086 }]
        }));
        assert!(image_config(&attestation).is_none());
        for media_type in [
            "application/vnd.oci.image.config.v1+json",
            "application/vnd.docker.container.image.v1+json",
            "application/octet-stream",
            "",
        ] {
            let image = parse(serde_json::json!({
                "config": { "mediaType": media_type, "digest": "sha256:cfg" },
                "layers": []
            }));
            assert_eq!(
                image_config(&image).map(|c| c.digest.as_str()),
                Some("sha256:cfg")
            );
        }
    }

    /// `record_matches_ref` replaces the crictl repoTags/repoDigests
    /// matcher — pin all three accepted shapes plus the registry-port
    /// corner case.
    #[test]
    fn record_matches_exact_tag_digest_and_name_only() {
        assert!(record_matches_ref(
            "docker.io/library/nginx:1.27",
            "docker.io/library/nginx:1.27"
        ));
        assert!(record_matches_ref(
            "docker.io/library/nginx@sha256:abc",
            "docker.io/library/nginx"
        ));
        assert!(record_matches_ref(
            "docker.io/library/nginx:1.27",
            "docker.io/library/nginx"
        ));
        assert!(!record_matches_ref(
            "docker.io/library/nginxy:1.27",
            "docker.io/library/nginx"
        ));
        // A registry port colon must not be mistaken for a tag separator.
        assert!(!record_matches_ref("localhost:5000/img", "localhost"));
    }

    /// Every name of a target is kept, deduplicated and sorted, with the
    /// latest update of any of its records, whatever order they are listed in.
    #[test]
    fn group_records_keeps_every_name() {
        let record = |name: &str, target: &str, updated: i64| ImageRecord {
            name: name.to_string(),
            target_digest: target.to_string(),
            updated: (updated, 0),
        };
        let mut records = vec![
            record("reg/app:1", "sha256:m", 5),
            record("reg/other:1", "sha256:i", 1),
            record("reg/app@sha256:m", "sha256:m", 9),
            record("sha256:0c0da35587", "sha256:m", 2),
        ];
        let key = |groups: Vec<RecordGroup>| -> Vec<(String, Vec<String>, Updated)> {
            groups
                .into_iter()
                .map(|g| (g.target, g.names, g.updated))
                .collect()
        };
        let first = key(group_records_by_target(&records));
        assert_eq!(
            first[1],
            (
                "sha256:m".to_string(),
                vec![
                    "reg/app:1".to_string(),
                    "reg/app@sha256:m".to_string(),
                    "sha256:0c0da35587".to_string()
                ],
                (9, 0)
            )
        );
        records.reverse();
        assert_eq!(key(group_records_by_target(&records)), first);
        records.swap(0, 1);
        assert_eq!(key(group_records_by_target(&records)), first);
    }

    /// REGRESSION (0.2.9-nydus mirrors EIO): containerd's CRI plugin stores a
    /// bare image-ID record (`sha256:<config digest>`) for every pulled
    /// image, and a daemon built from it fetched blobs from repo
    /// "library/sha256". The image-ID record is never a served name.
    #[test]
    fn best_name_never_selects_bare_image_id() {
        let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let id = "sha256:0c0da3558734bbf673448b752bb6c139cbd3ece8060c6589370280b8ba631d9e";
        assert_eq!(
            best_name(&names(&[id, "docker.io/example/app@sha256:2a25"])),
            "docker.io/example/app@sha256:2a25"
        );
        assert_eq!(
            best_name(&names(&[
                "docker.io/library/nginx@sha256:abc",
                "docker.io/library/nginx:1.27"
            ])),
            "docker.io/library/nginx:1.27"
        );
        assert_eq!(best_name(&names(&["reg/a:2", "reg/a:1"])), "reg/a:1");
    }

    #[test]
    fn ref_name_rank_orders_tag_over_digest_over_bare() {
        assert_eq!(ref_name_rank("docker.io/library/nginx:1.27"), 3);
        assert_eq!(ref_name_rank("docker.io/library/nginx@sha256:abc"), 2);
        assert_eq!(ref_name_rank("docker.io/library/nginx"), 1);
        assert_eq!(ref_name_rank("localhost:5000/img"), 1); // port, not tag
        assert_eq!(
            ref_name_rank("sha256:0c0da3558734bbf673448b752bb6c139cbd3ece806"),
            0
        );
    }

    #[test]
    fn repository_of_refs() {
        assert_eq!(repository("localhost:5000/app"), Some("localhost:5000/app"));
        assert_eq!(
            repository("localhost:5000/app:1"),
            Some("localhost:5000/app")
        );
        assert_eq!(repository("reg/app@sha256:abc"), Some("reg/app"));
        assert_eq!(repository("sha256:abc"), None);
    }

    /// Two images whose configs share a top chainID: the chain names
    /// neither image, whatever order the image store lists or walks them in.
    #[test]
    fn shared_top_chain_answers_no_single_image() {
        let diff_ids = vec!["sha256:base".to_string(), "sha256:app".to_string()];
        let top = chain_ids(&diff_ids).last().unwrap().clone();
        let images = [
            ("sha256:a-manifest", "reg/claimant-a:1"),
            ("sha256:b-index", "reg/claimant-b:1"),
            ("sha256:other", "reg/other:2"),
        ];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let lookup = ContainerdLookup::new_cli_only();
            for (updated, i) in order.into_iter().enumerate() {
                let (target, image_ref) = images[i];
                let mut out = HashMap::new();
                if i < 2 {
                    register_chain_ids(image_ref, &diff_ids, &[], &mut out);
                }
                let digests: Vec<&str> = out.keys().map(String::as_str).collect();
                lookup.seed(NS, target, &[image_ref], updated as i64, &digests);
            }
            assert_eq!(
                lookup.lookup_cached(NS, &top).unwrap(),
                Claim::Ambiguous(vec![
                    "reg/claimant-a".to_string(),
                    "reg/claimant-b".to_string()
                ]),
                "order {order:?}"
            );
        }
    }
}
