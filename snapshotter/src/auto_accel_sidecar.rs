// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Sidecar discovery + backend-dir staging for the auto-accel read side.
//!
//! When `OverlayEngine::prepare` returns plain overlay mounts for a standard
//! OCI image, [`SidecarLocator::find`] asks containerd's content store
//! whether an auto-accel manifest exists for the image's manifest digest. If
//! one is mirrored locally (either because this node produced it or because
//! spegel replicated it from a peer), [`stage_backend`] symlinks the gzip
//! layers + per-layer zran indexes + optional prefetch blob into a fresh
//! `backend/` directory and copies the merged bootstrap into a `stage/`
//! directory. The result feeds straight into
//! `DaemonSupervisor::ensure_instance_local`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tracing::{debug, info, warn};

use crate::auto_zran::AutoAccelManifest;
use crate::content_store::{ContentInfo, ContentStoreClient};

const LABEL_ROLE: &str = "containerd.io/snapshot/nydus.auto-accel.role";
const LABEL_SUBJECT: &str = "containerd.io/gc.ref.content.subject";

/// A resolved auto-accel sidecar with its on-disk paths ready for the fanotify
/// backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedSidecar {
    /// Copied merged bootstrap inside the per-image stage dir.
    pub bootstrap: PathBuf,
    /// Backend dir holding gzip-layer symlinks + zran index blobs + the
    /// optional prefetch blob.
    pub backend_dir: PathBuf,
    /// Root of the per-image scratch (parent of `bootstrap` and
    /// `backend_dir`). Removed by the supervisor on instance teardown.
    pub work_dir: PathBuf,
}

/// Sidecar lookup against containerd's content store. Cheap to clone.
#[derive(Clone)]
pub struct SidecarLocator {
    content_store: ContentStoreClient,
    /// Snapshotter root joined with `"auto-accel"`; per-image scratch dirs
    /// hang off this.
    stage_root: PathBuf,
}

impl SidecarLocator {
    pub fn new(content_store: ContentStoreClient, snapshotter_root: &Path) -> Self {
        Self {
            content_store,
            stage_root: snapshotter_root.join("auto-accel"),
        }
    }

    /// Resolve an auto-accel manifest for `manifest_digest`, pulling it
    /// from a peer via spegel when not already local. Tries in order:
    ///
    /// 1. Local `images.Get(synthetic-ref)` — hit on the producer node and
    ///    on any peer that already pulled this sidecar.
    /// 2. `ctr -n k8s.io image pull <synthetic-ref>` — drives containerd's
    ///    Resolver through `registries.yaml`'s `mirrors:{"+":...}` config,
    ///    which routes to k3s's embedded spegel. spegel asks peers via
    ///    libp2p; if a peer has the image record advertised, the OCI
    ///    manifest + its config + every layer (bootstrap, zran indexes,
    ///    prefetch blob) flow through the mirror in one transfer. After
    ///    success we retry `images.Get`. A categorised pull failure
    ///    distinguishes "no peer has it" (clean miss) from "mirror /
    ///    registry is broken" (warn + still fall through, but operator
    ///    sees the signal).
    /// 3. Label-filter scan on the content store — covers legacy artifacts
    ///    uploaded before the image-record registration landed.
    ///
    /// Returns `Ok(None)` when nothing matches — the caller falls back to
    /// overlay. Named for the actual behaviour (not just a read-only
    /// "find") so callers see the mutation.
    pub async fn resolve_or_pull(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<AutoAccelManifest>> {
        let image_name = crate::auto_zran::auto_accel_image_name(manifest_digest);

        let mut resolved = self
            .content_store
            .images_get(&image_name)
            .await
            .unwrap_or_else(|e| {
                debug!(image_name = %image_name, error = %e, "auto-accel images.Get failed; will try pull");
                None
            });

        if resolved.is_none() {
            // Drive a containerd pull through registries.yaml → spegel →
            // peer. If a peer advertises the image record, this brings
            // everything down in one shot.
            match ctr_image_pull(&image_name).await {
                PullOutcome::Ok => {
                    info!(image_name = %image_name, "auto-accel pulled via spegel mirror");
                    resolved = self
                        .content_store
                        .images_get(&image_name)
                        .await
                        .unwrap_or_else(|e| {
                            debug!(image_name = %image_name, error = %e, "post-pull images.Get failed");
                            None
                        });
                }
                PullOutcome::NotFound => {
                    debug!(image_name = %image_name, "no peer advertised this sidecar; falling back to label scan");
                }
                PullOutcome::RegistryError { stderr, exit_code } => {
                    // Real configuration failure — surface loudly. Without
                    // this every pod on a misconfigured-spegel node would
                    // silently degrade to overlay forever.
                    warn!(
                        image_name = %image_name,
                        exit_code,
                        stderr = %stderr,
                        "auto-accel pull failed: registry/mirror error (spegel mTLS, auth, daemon down?). Cross-node discovery disabled until fixed."
                    );
                }
                PullOutcome::NoBinary => {
                    warn!(image_name = %image_name, "auto-accel pull skipped: neither `ctr` nor `k3s ctr` runnable");
                }
            }
        }

        let blob = match resolved {
            Some(info) => info,
            None => {
                // Label-filter fallback (legacy artifacts).
                let filters = vec![format!(
                    "labels.\"{LABEL_SUBJECT}\"=={manifest_digest},labels.\"{LABEL_ROLE}\"==manifest"
                )];
                let blobs = self.content_store.list_with_filters(filters).await?;
                let Some(blob) = pick_latest_manifest(&blobs).cloned() else {
                    return Ok(None);
                };
                blob
            }
        };

        // The Image record points at the OCI manifest. Parse it, fetch the
        // referenced config blob (which is our AutoAccelManifest JSON), and
        // return that to the caller.
        let manifest_bytes = self.content_store.fetch_bytes(&blob.digest).await?;
        let oci: serde_json::Value = serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("parse oci wrapper for {}", blob.digest))?;
        let config_digest = oci
            .get("config")
            .and_then(|c| c.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| anyhow!("oci manifest {} missing config.digest", blob.digest))?
            .to_string();
        let config_bytes = self.content_store.fetch_bytes(&config_digest).await?;
        let manifest: AutoAccelManifest = serde_json::from_slice(&config_bytes)
            .with_context(|| format!("parse auto-accel config blob {config_digest}"))?;
        if manifest.subject_manifest_digest != manifest_digest {
            warn!(
                expected = manifest_digest,
                got = manifest.subject_manifest_digest,
                "auto-accel manifest subject mismatch; ignoring"
            );
            return Ok(None);
        }
        if manifest.version != 1 {
            debug!(
                version = manifest.version,
                "auto-accel manifest is newer than this snapshotter supports; ignoring"
            );
            return Ok(None);
        }
        info!(
            subject = manifest_digest,
            bootstrap = %manifest.bootstrap.digest,
            indexes = manifest.zran_indexes.len(),
            "auto-accel sidecar discovered"
        );
        Ok(Some(manifest))
    }

    /// Stage a backend directory with symlinks to all referenced blobs in
    /// containerd's content store, copy the merged bootstrap into a
    /// `stage/bootstrap` file. Idempotent: re-staging the same manifest
    /// is a no-op (the symlinks are recreated, the bootstrap is overwritten).
    pub async fn stage(
        &self,
        manifest_digest: &str,
        manifest: &AutoAccelManifest,
    ) -> Result<StagedSidecar> {
        let work_dir = self.stage_root.join(slug_for_digest(manifest_digest));
        let backend_dir = work_dir.join("backend");
        let stage_dir = work_dir.join("stage");
        std::fs::create_dir_all(&backend_dir)
            .with_context(|| format!("create auto-accel backend dir {}", backend_dir.display()))?;
        std::fs::create_dir_all(&stage_dir)
            .with_context(|| format!("create auto-accel stage dir {}", stage_dir.display()))?;

        // 1. Symlink each gzip layer (already in containerd's content store)
        //    into backend_dir/<bare-hex>. nydus's localfs backend keys blobs
        //    by their bare blob_id (no algorithm prefix).
        for layer in &manifest.zran_indexes {
            let layer_path = self.content_store.blob_path(&layer.layer_digest);
            ensure_present(&layer_path, "gzip layer")?;
            let link = backend_dir.join(strip_sha256(&layer.layer_digest));
            symlink_force(&layer_path, &link)?;

            // 2. Symlink each zran index blob the same way.
            let index_path = self.content_store.blob_path(&layer.digest);
            ensure_present(&index_path, "zran index")?;
            let index_link = backend_dir.join(strip_sha256(&layer.digest));
            symlink_force(&index_path, &index_link)?;
        }

        // 3. Symlink the optional prefetch blob.
        if let Some(prefetch) = &manifest.prefetch_blob {
            let path = self.content_store.blob_path(&prefetch.digest);
            ensure_present(&path, "prefetch blob")?;
            let link = backend_dir.join(strip_sha256(&prefetch.digest));
            symlink_force(&path, &link)?;
        }

        // 4. Copy the merged bootstrap into the stage dir under the
        //    `bootstrap` name the fanotify handler expects. We use copy
        //    (not symlink) because the bootstrap is small and copy avoids
        //    the fanotify handler ever resolving a dangling link.
        let bootstrap_src = self.content_store.blob_path(&manifest.bootstrap.digest);
        ensure_present(&bootstrap_src, "bootstrap")?;
        let bootstrap_dst = stage_dir.join("bootstrap");
        std::fs::copy(&bootstrap_src, &bootstrap_dst).with_context(|| {
            format!(
                "copy bootstrap {} -> {}",
                bootstrap_src.display(),
                bootstrap_dst.display()
            )
        })?;

        Ok(StagedSidecar {
            bootstrap: bootstrap_dst,
            backend_dir,
            work_dir,
        })
    }
}

/// When multiple auto-accel manifests claim the same subject (e.g. two nodes
/// converted with different prefetch profiles), prefer whichever blob has the
/// largest size — heuristically the most-complete profile. Fall back to the
/// lexicographically-largest digest for stable ordering when sizes match.
fn pick_latest_manifest(blobs: &[ContentInfo]) -> Option<&ContentInfo> {
    let mut best: Option<&ContentInfo> = None;
    for blob in blobs {
        match best {
            None => best = Some(blob),
            Some(prev) if blob.size > prev.size => best = Some(blob),
            Some(prev) if blob.size == prev.size && blob.digest > prev.digest => best = Some(blob),
            _ => {}
        }
    }
    best
}

fn ensure_present(path: &Path, kind: &str) -> Result<()> {
    if !path.is_file() {
        return Err(anyhow!(
            "{kind} {} missing from content store (spegel cache miss?)",
            path.display()
        ));
    }
    Ok(())
}

fn symlink_force(target: &Path, link: &Path) -> Result<()> {
    let _ = std::fs::remove_file(link);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
            .with_context(|| format!("symlink {} -> {}", link.display(), target.display()))
    }
    #[cfg(not(unix))]
    {
        std::fs::copy(target, link)
            .map(|_| ())
            .with_context(|| format!("copy {} -> {}", link.display(), target.display()))
    }
}

fn strip_sha256(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

/// Categorised outcome of a containerd image-pull attempt for the
/// synthetic auto-accel ref. Discovery treats `NotFound` as a clean miss
/// (no peer advertised this sidecar — fall back to overlay) but logs
/// `RegistryError` at `warn!` so a broken spegel mirror or stale mTLS
/// doesn't silently disable every auto-accel mount cluster-wide.
#[derive(Debug, Clone, Eq, PartialEq)]
enum PullOutcome {
    /// Pull committed; the manifest is now in the local content store.
    Ok,
    /// Resolver returned a 404 / NotFound — no peer advertises this ref.
    /// Expected on first-pod scheduling before any node has converted.
    NotFound,
    /// `ctr` ran and failed with something OTHER than NotFound. Examples:
    /// 401/403 (spegel auth misconfigured), DNS lookup error not at the
    /// "synthetic host doesn't resolve" tail of the chain, daemon-not-
    /// running, flag-parse skew on a version mismatch. Captured for
    /// triage.
    RegistryError { stderr: String, exit_code: i32 },
    /// Couldn't spawn any candidate binary at all.
    NoBinary,
}

/// Attempt a containerd image pull for the synthetic auto-accel ref. We
/// shell out to `ctr` (rather than wire up the containerd Transfer service
/// in tonic) because pull is one-shot work and behind a best-effort
/// fallback. Categorising the failure mode (vs collapsing every error
/// into `Ok(false)` as the earlier version did) lets discovery log loudly
/// when the mirror itself is broken — previously a node with broken
/// spegel mTLS would have every auto-accel mount silently degrade to
/// overlay forever with no signal.
async fn ctr_image_pull(image_name: &str) -> PullOutcome {
    let image_name = image_name.to_string();
    blocking::unblock(move || {
        let mut last_failure: Option<PullOutcome> = None;
        for argv in &[
            vec![
                "ctr",
                "-n",
                "k8s.io",
                "image",
                "pull",
                "--plain-http=false",
                &image_name,
            ],
            vec![
                "k3s",
                "ctr",
                "-n",
                "k8s.io",
                "image",
                "pull",
                "--plain-http=false",
                &image_name,
            ],
        ] {
            let mut cmd = std::process::Command::new(argv[0]);
            cmd.args(&argv[1..]);
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::piped());
            let output = match cmd.output() {
                Ok(o) => o,
                Err(e) => {
                    debug!(error = %e, argv = ?argv, "ctr image pull failed to spawn; trying next");
                    continue;
                }
            };
            if output.status.success() {
                return PullOutcome::Ok;
            }
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            let exit_code = output.status.code().unwrap_or(-1);
            last_failure = Some(classify_pull_failure(&stderr, exit_code));
            // Same binary version of containerd answers both `ctr` and
            // `k3s ctr` — if the first ran and gave a categorised failure
            // the second will too. Only spawn-failure (the `continue`
            // above) tries the next candidate.
            return last_failure.unwrap();
        }
        last_failure.unwrap_or(PullOutcome::NoBinary)
    })
    .await
}

/// Map `ctr image pull` stderr + exit code to a `PullOutcome`. Pulled out
/// of `ctr_image_pull` so unit tests can pin the categorisation without
/// spawning a process.
fn classify_pull_failure(stderr: &str, exit_code: i32) -> PullOutcome {
    let lower = stderr.to_ascii_lowercase();
    // Spegel + missing real registry produces the literal "not found"
    // from the resolver. `dial tcp: lookup …: no such host` is also the
    // miss path — the synthetic `.local` hostname doesn't resolve and
    // the mirror chain had no peer answer either, so reaching the host
    // lookup means resolve already 404'd.
    let is_not_found = lower.contains("not found")
        || lower.contains("no such host")
        || lower.contains("manifest unknown")
        || lower.contains("404");
    if is_not_found {
        PullOutcome::NotFound
    } else {
        PullOutcome::RegistryError {
            stderr: stderr.to_string(),
            exit_code,
        }
    }
}

/// Per-manifest slug for staging dirs. Uses the bare hex (no `sha256:`
/// prefix) so the resulting path is short and `ls`-friendly.
fn slug_for_digest(manifest_digest: &str) -> String {
    let hex = strip_sha256(manifest_digest);
    // 16 chars is plenty for collision avoidance in the per-manifest scratch
    // namespace; the full digest already lives in the auto-accel manifest.
    hex[..hex.len().min(16)].to_string()
}

/// Top-level "owns" wrapper for the sidecar locator + the result of one
/// resolution. Constructed in `serve_with_supervisor` only when auto-accel
/// is enabled. Held in `Arc` so cloning is cheap.
#[derive(Clone)]
pub struct AutoAccelDiscovery {
    pub locator: Arc<SidecarLocator>,
}

impl AutoAccelDiscovery {
    pub fn new(content_store: ContentStoreClient, snapshotter_root: &Path) -> Self {
        Self {
            locator: Arc::new(SidecarLocator::new(content_store, snapshotter_root)),
        }
    }

    /// One-shot helper: resolve-or-pull + stage in one call. Returns
    /// `Ok(None)` if no sidecar exists; the caller falls back to overlay.
    pub async fn resolve(&self, manifest_digest: &str) -> Result<Option<StagedSidecar>> {
        let Some(manifest) = self.locator.resolve_or_pull(manifest_digest).await? else {
            return Ok(None);
        };
        let staged = self.locator.stage(manifest_digest, &manifest).await?;
        Ok(Some(staged))
    }
}

/// Convenience: the canonical label set the auto-zran worker stamps on each
/// uploaded artifact. Re-exported so callers can verify in tests or logs.
pub fn auto_accel_labels(subject: &str, role: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(LABEL_SUBJECT.to_string(), subject.to_string());
    m.insert(LABEL_ROLE.to_string(), role.to_string());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_latest_prefers_larger_size_then_digest() {
        let a = ContentInfo {
            digest: "sha256:aaa".into(),
            size: 10,
            labels: HashMap::new(),
        };
        let b = ContentInfo {
            digest: "sha256:bbb".into(),
            size: 20,
            labels: HashMap::new(),
        };
        let c = ContentInfo {
            digest: "sha256:ccc".into(),
            size: 20,
            labels: HashMap::new(),
        };
        let blobs = vec![a.clone(), b.clone(), c.clone()];
        assert_eq!(pick_latest_manifest(&blobs).unwrap().digest, "sha256:ccc");
        let blobs = vec![a, b];
        assert_eq!(pick_latest_manifest(&blobs).unwrap().digest, "sha256:bbb");
    }

    #[test]
    fn slug_for_digest_strips_prefix_and_truncates() {
        assert_eq!(
            slug_for_digest("sha256:abcdef1234567890abcdef1234567890"),
            "abcdef1234567890"
        );
        assert_eq!(slug_for_digest("abc"), "abc");
    }

    /// `classify_pull_failure` is the critical bit of `ctr_image_pull`:
    /// it decides whether a non-zero exit is a clean "no peer has it"
    /// miss (silent fallback to overlay) or a real "mirror is broken"
    /// signal that needs operator attention. Pre-fix the categorisation
    /// was missing and a busted spegel mTLS would have silently
    /// disabled every auto-accel mount on the node.
    #[test]
    fn classify_pull_failure_treats_404_as_not_found() {
        assert_eq!(
            classify_pull_failure("ctr: failed to resolve image: manifest unknown", 1),
            PullOutcome::NotFound
        );
    }

    #[test]
    fn classify_pull_failure_treats_dns_lookup_as_not_found() {
        // Synthetic host `nydus.auto-accel.local` deliberately doesn't
        // resolve — when spegel finds no peer the fallback fails DNS,
        // which is a clean miss not a real error.
        let stderr = "ctr: failed to do request: Head \"https://nydus.auto-accel.local/v2/sidecar/manifests/X\": dial tcp: lookup nydus.auto-accel.local: no such host";
        assert_eq!(classify_pull_failure(stderr, 1), PullOutcome::NotFound);
    }

    #[test]
    fn classify_pull_failure_treats_404_status_word_as_not_found() {
        assert_eq!(
            classify_pull_failure("HTTP 404 Not Found", 1),
            PullOutcome::NotFound
        );
    }

    #[test]
    fn classify_pull_failure_flags_auth_as_registry_error() {
        // 401/403 / "unauthorized" / spegel mTLS misconfig — operator
        // needs the signal. NOT a silent fallback.
        let stderr = "ctr: failed to resolve image: failed to fetch manifest: 401 Unauthorized";
        match classify_pull_failure(stderr, 1) {
            PullOutcome::RegistryError { exit_code, .. } => assert_eq!(exit_code, 1),
            other => panic!("expected RegistryError for auth failure, got {other:?}"),
        }
    }

    #[test]
    fn classify_pull_failure_flags_daemon_down_as_registry_error() {
        let stderr = "ctr: failed to dial: connection refused";
        match classify_pull_failure(stderr, 1) {
            PullOutcome::RegistryError { .. } => {}
            other => panic!("expected RegistryError for daemon-down, got {other:?}"),
        }
    }
}
