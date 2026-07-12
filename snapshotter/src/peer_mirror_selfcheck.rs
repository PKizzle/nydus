// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Local peer-mirror self-diagnostic.
//!
//! This converts a *silent* failure class into a diagnosable one. On the
//! 2026-07 `canary-node` incident a single mistyped character in
//! `/etc/rancher/k3s/registries.yaml` (`mirrors: "+"` instead of `"*"`) left
//! the node's embedded Spegel mirror advertising nothing, so cross-node
//! acceleration invisibly fell back to full image extraction for months. The
//! snapshotter's own logs were clean — the mirror answered, it just never
//! offered local content — so nothing flagged it.
//!
//! The self-check closes that gap: it picks a digest **known to be in this
//! node's content store** (a node-local auto-accel sidecar this node itself
//! produced and registered as an Image record — exactly the content peers need
//! to fetch) and GETs it from ONLY the local mirror endpoint via
//! [`PeerMirror::probe_local`] (no peer fan-out — a peer answering would say
//! nothing about the LOCAL mirror). The response is classified:
//!
//! - **200** ⇒ healthy: the local mirror is advertising local content.
//! - **404** ⇒ the failure mode: the embedded registry is NOT advertising local
//!   content. A LOUD, actionable warning names the exact causes we lived
//!   through.
//! - **transport/other error** ⇒ the local mirror endpoint is unreachable.
//!
//! The result is surfaced as the `snapshotter_peer_mirror_selfcheck_ok` gauge
//! (0/1) so it can alert. When no local sidecar exists yet (fresh node, no
//! conversions) the check is skipped without touching the metric — there is
//! nothing local to advertise, so the check is moot, and we never fabricate a
//! digest to probe.
//!
//! The whole thing is best-effort: every failure is logged and swallowed, and
//! it runs on its own detached background loop so it can never block or crash
//! startup.
//!
//! **Scope limitation:** because the only guaranteed-local, Spegel-advertised
//! digest we can probe is a node-local auto-accel sidecar, the loop is wired
//! (in `grpc::serve_with_supervisor`) inside the `auto_zran.enable` block — a
//! node running `peer_mirror` *without* `auto_zran` never self-checks. That is
//! inherent to the digest-source design, not an oversight: without a locally
//! produced artifact there is nothing the mirror is expected to advertise.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::config::PeerMirrorConfig;
use crate::content_store::ContentStoreClient;
use crate::metrics::SnapshotterMetrics;
use crate::peer_mirror::{FetchResult, PeerMirror, build_peer_mirror};

/// Host prefix of the node-local auto-accel synthetic image ref
/// (`nydus.auto-accel.local/sidecar:<hex>`, see
/// [`crate::auto_zran::auto_accel_image_name`]). Image records whose name
/// starts with this are sidecars this node produced — guaranteed-local content
/// the embedded mirror should be advertising.
const AUTO_ACCEL_HOST_PREFIX: &str = "nydus.auto-accel.local/";

/// Accept header for the manifest probe — mirror the media types the sidecar
/// producer/consumer use so a correctly-advertising mirror returns the body
/// rather than a 406.
const ACCEPT_MANIFEST: &str = concat!(
    "application/vnd.oci.image.manifest.v1+json,",
    "application/vnd.docker.distribution.manifest.v2+json"
);

/// How long after startup the first probe waits (let a converted sidecar or a
/// pulled image settle) and the steady-state re-probe cadence.
const SELFCHECK_INTERVAL: Duration = Duration::from_secs(300);

/// Classified outcome of one local-mirror probe. Pure over a [`FetchResult`]
/// so the 200-vs-404-vs-error boundary is unit-testable without HTTP.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SelfCheckStatus {
    /// 200: the local mirror served a known-local digest — advertising works.
    Healthy,
    /// 404: the local mirror does not advertise local content (the 4-1 class).
    NotAdvertising,
    /// Transport / non-404 error: the local mirror endpoint is unreachable or
    /// misbehaving. `detail` carries the richest triage string available.
    Unreachable { detail: String },
}

impl SelfCheckStatus {
    /// Whether this maps to the `snapshotter_peer_mirror_selfcheck_ok == 1`
    /// (healthy) state. Both `NotAdvertising` and `Unreachable` are `false`.
    fn is_ok(&self) -> bool {
        matches!(self, SelfCheckStatus::Healthy)
    }
}

/// Map a local-mirror probe [`FetchResult`] into a [`SelfCheckStatus`]. Pure.
fn classify(result: &FetchResult) -> SelfCheckStatus {
    match result {
        FetchResult::Ok(_) => SelfCheckStatus::Healthy,
        FetchResult::NotFound => SelfCheckStatus::NotAdvertising,
        FetchResult::Error { status, body } => SelfCheckStatus::Unreachable {
            detail: format!("HTTP {status}: {body}"),
        },
        FetchResult::Outcome(outcome) => SelfCheckStatus::Unreachable {
            detail: format!("{outcome:?}"),
        },
    }
}

/// Build the `/v2/<repo>/manifests/<digest>` path (plus the mirror's query
/// parameter) for a node-local auto-accel sidecar image ref. Returns `None`
/// when `name` is not a well-formed sidecar ref. Pure so tests can pin the
/// shape. `query` is the already-expanded mirror query (e.g. `ns=<host>`).
fn probe_path_for_sidecar(
    name: &str,
    target_digest: &str,
    query: &Option<String>,
) -> Option<String> {
    // name == "nydus.auto-accel.local/sidecar:<hex>"
    let (host, rest) = name.split_once('/')?;
    if host.is_empty() {
        return None;
    }
    // Strip the ":<tag>" — we probe by the manifest digest, not the tag, so
    // the check is an unambiguous "is this exact local blob served" test.
    let repo = rest.rsplit_once(':').map(|(repo, _)| repo).unwrap_or(rest);
    if repo.is_empty() || target_digest.is_empty() {
        return None;
    }
    let base = format!("/v2/{repo}/manifests/{target_digest}");
    Some(match query {
        Some(q) if !q.is_empty() => format!("{base}?{q}"),
        _ => base,
    })
}

/// Local peer-mirror self-diagnostic. Cheap to construct; holds only handles.
pub struct PeerMirrorSelfCheck {
    content_store: ContentStoreClient,
    peer_mirror: Arc<PeerMirror>,
    metrics: Arc<SnapshotterMetrics>,
}

impl PeerMirrorSelfCheck {
    /// Build the self-check from config. Returns `None` when the peer mirror is
    /// disabled or its client can't be constructed (missing TLS material, etc.)
    /// — there is then nothing to self-check.
    pub fn from_config(
        content_store: ContentStoreClient,
        cfg: &PeerMirrorConfig,
        metrics: Arc<SnapshotterMetrics>,
    ) -> Option<Self> {
        let peer_mirror = match build_peer_mirror(cfg) {
            Ok(Some(m)) => m,
            Ok(None) => return None,
            Err(e) => {
                warn!(error = ?e, "peer mirror self-check: mirror client build failed; self-check disabled");
                return None;
            }
        };
        Some(Self {
            content_store,
            peer_mirror,
            metrics,
        })
    }

    /// Background loop: an initial probe after a settle delay, then a re-probe
    /// every [`SELFCHECK_INTERVAL`]. Runs forever; each iteration is
    /// best-effort and never propagates an error.
    pub async fn run_loop(self) {
        info!(
            endpoint = %self.peer_mirror.primary_endpoint(),
            "peer mirror self-check: starting local-mirror diagnostic loop"
        );
        loop {
            compio::time::sleep(SELFCHECK_INTERVAL).await;
            self.run_once().await;
        }
    }

    /// Run one self-check: source a known-local digest, probe the local mirror,
    /// classify, log, and update the metric. Skips (no metric update) when no
    /// local sidecar exists to probe. Never panics; logs and returns on error.
    pub async fn run_once(&self) {
        let (name, digest) = match self.local_sidecar_digest().await {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                debug!(
                    "peer mirror self-check: no node-local sidecar to probe yet; skipping \
                     (nothing local to advertise)"
                );
                return;
            }
            Err(e) => {
                warn!(error = ?e, "peer mirror self-check: could not list local sidecars; skipping");
                return;
            }
        };

        let query = self.peer_mirror.artifact_query(host_of(&name));
        let Some(path) = probe_path_for_sidecar(&name, &digest, &query) else {
            debug!(image = %name, "peer mirror self-check: sidecar ref not well-formed; skipping");
            return;
        };

        let result = self
            .peer_mirror
            .probe_local(&path, Some(ACCEPT_MANIFEST))
            .await;
        let status = classify(&result);
        self.metrics.set_peer_mirror_selfcheck(status.is_ok());
        self.report(&status, &name, &digest);
    }

    /// Find a digest guaranteed to be in this node's content store: a
    /// node-local auto-accel sidecar this node produced (registered as an Image
    /// record, hence advertised by the embedded mirror). Returns the synthetic
    /// ref name + its manifest digest, or `None` when none exists yet.
    async fn local_sidecar_digest(&self) -> anyhow::Result<Option<(String, String)>> {
        let images = self.content_store.images_list().await?;
        Ok(images
            .into_iter()
            .find(|img| {
                img.name.starts_with(AUTO_ACCEL_HOST_PREFIX) && !img.target_digest.is_empty()
            })
            .map(|img| (img.name, img.target_digest)))
    }

    /// Emit the operator-facing log line for a classified result.
    fn report(&self, status: &SelfCheckStatus, image: &str, digest: &str) {
        let endpoint = self.peer_mirror.primary_endpoint();
        match status {
            SelfCheckStatus::Healthy => {
                info!(
                    endpoint = %endpoint,
                    image = %image,
                    "peer mirror self-check OK: the local mirror is advertising local content"
                );
            }
            SelfCheckStatus::NotAdvertising => {
                warn!(
                    endpoint = %endpoint,
                    image = %image,
                    digest = %digest,
                    "PEER MIRROR SELF-CHECK FAILED: the local mirror returned 404 for a digest \
                     KNOWN to be in this node's content store — the embedded registry is NOT \
                     advertising local content to peers. Cross-node auto-acceleration will \
                     silently fall back to full image extraction on peers. Likely causes: \
                     (1) /etc/rancher/k3s/registries.yaml `mirrors:` uses the wrong key — it \
                     MUST be `\"*\":` (a wrong key such as `\"+\":` silently disables local \
                     content advertisement, the canary-node incident); \
                     (2) node CPU / etcd health is degraded so the embedded mirror cannot \
                     advertise. Verify registries.yaml and node/etcd load."
                );
            }
            SelfCheckStatus::Unreachable { detail } => {
                warn!(
                    endpoint = %endpoint,
                    image = %image,
                    detail = %detail,
                    "peer mirror self-check: the local mirror endpoint is unreachable or \
                     misbehaving. Peer discovery and cross-node sidecar pulls will not work \
                     until it responds. Check that the embedded mirror (k3s Spegel) is running \
                     and that the configured endpoint / mTLS material is correct."
                );
            }
        }
    }
}

/// The host segment of a sidecar ref (`<host>/<repo>:<tag>` → `<host>`), or the
/// whole string when there is no `/`.
fn host_of(name: &str) -> &str {
    name.split_once('/').map(|(host, _)| host).unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_mirror::PullOutcome;

    #[test]
    fn classify_maps_status_to_selfcheck() {
        assert_eq!(
            classify(&FetchResult::Ok(vec![1, 2, 3])),
            SelfCheckStatus::Healthy
        );
        assert_eq!(
            classify(&FetchResult::NotFound),
            SelfCheckStatus::NotAdvertising
        );
        // 200 is the only "ok" state; the failure modes both gauge to 0.
        assert!(classify(&FetchResult::Ok(vec![])).is_ok());
        assert!(!classify(&FetchResult::NotFound).is_ok());

        let err = classify(&FetchResult::Error {
            status: 503,
            body: "unavailable".to_string(),
        });
        assert!(matches!(err, SelfCheckStatus::Unreachable { .. }));
        assert!(!err.is_ok());

        let outcome = classify(&FetchResult::Outcome(PullOutcome::RegistryError {
            status: 0,
            body: "connection refused".to_string(),
        }));
        assert!(matches!(outcome, SelfCheckStatus::Unreachable { .. }));
    }

    #[test]
    fn probe_path_builds_manifest_path_by_digest() {
        let query = Some("ns=nydus.auto-accel.local".to_string());
        let path = probe_path_for_sidecar(
            "nydus.auto-accel.local/sidecar:e6017bb",
            "sha256:abc123",
            &query,
        )
        .expect("well-formed sidecar ref");
        assert_eq!(
            path,
            "/v2/sidecar/manifests/sha256:abc123?ns=nydus.auto-accel.local"
        );
    }

    #[test]
    fn probe_path_without_query_omits_question_mark() {
        let path = probe_path_for_sidecar(
            "nydus.auto-accel.local/sidecar:e6017bb",
            "sha256:abc",
            &None,
        )
        .expect("well-formed sidecar ref");
        assert_eq!(path, "/v2/sidecar/manifests/sha256:abc");
        // An empty (Some("")) query is likewise omitted.
        let path = probe_path_for_sidecar(
            "nydus.auto-accel.local/sidecar:e6017bb",
            "sha256:abc",
            &Some(String::new()),
        )
        .unwrap();
        assert_eq!(path, "/v2/sidecar/manifests/sha256:abc");
    }

    #[test]
    fn probe_path_rejects_malformed_refs() {
        // No '/': no host/repo split.
        assert!(probe_path_for_sidecar("nydus.auto-accel.local", "sha256:abc", &None).is_none());
        // Empty digest.
        assert!(probe_path_for_sidecar("nydus.auto-accel.local/sidecar:t", "", &None).is_none());
        // Empty repo (host + empty repo before tag).
        assert!(probe_path_for_sidecar("host/:t", "sha256:abc", &None).is_none());
    }

    #[test]
    fn host_of_extracts_host_segment() {
        assert_eq!(
            host_of("nydus.auto-accel.local/sidecar:t"),
            "nydus.auto-accel.local"
        );
        assert_eq!(host_of("no-slash"), "no-slash");
    }
}
