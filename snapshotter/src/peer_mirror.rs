// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! HTTP client for a peer registry mirror, with optional automatic peer
//! discovery. k3s' embedded Spegel is the reference implementation (the
//! `k3s-spegel` preset); the transport here is mirror-agnostic.
//!
//! The auto-accel consumer pulls sidecar artifacts through the mirror's
//! distribution endpoint (`/v2/...` plus the preset's query template — for
//! Spegel that is the load-bearing `?ns=<registry>` parameter, without which
//! Spegel's distribution.go parser 404s every path).
//!
//! ## Kubernetes peer discovery (opt-in resilience fallback)
//!
//! `peer_discovery = kubernetes` bypasses the mirror's own libp2p routing:
//! it discovers the cluster's node IPs from the Kubernetes API — using the
//! same mTLS identity the mirror endpoint already requires — and walks each
//! peer's mirror endpoint directly. This routes around provider-record rot
//! observed on THIS cluster with the k3s-bundled **Spegel v0.4.0-k3s3** DHT
//! ("could not find peer" / "empty list of address ports" for content that
//! peers demonstrably hold).
//!
//! Native DHT routing is now **verified working** on the cluster's current
//! **Spegel v0.7.1-k3s1**, so `peer_discovery` defaults to `off` for EVERY
//! preset (including `k3s-spegel`): the local mirror plus Spegel's own libp2p
//! routing is the primary path. The `kubernetes` node fan-out remains an
//! explicit operator opt-in — a resilience fallback for per-node Spegel
//! failure — and is scheduled for removal after a production soak of
//! default-off (the code is kept until then). When it is enabled, the
//! snapshotter logs a one-time deprecation warning at startup.
//!
//! ## Local-mirror self-check
//!
//! [`PeerMirror::probe_local`] issues a GET against ONLY the local (primary)
//! endpoint — no peer fan-out — so a caller can verify the embedded mirror is
//! advertising a digest known to be in this node's content store. This
//! diagnoses the silent-failure class where a mistyped `registries.yaml`
//! `mirrors:` key (a stray `"+"` instead of `"*"`) leaves the local mirror
//! serving nothing, invisibly disabling cross-node acceleration. See
//! [`crate::peer_mirror_selfcheck`].
//!
//! Failover semantics live in [`PeerMirror::fetch`]: primary (local
//! mirror) first, then discovered + static peers in rotated order, a
//! short per-request timeout, and a cooldown that skips peers that
//! recently failed at the transport layer.
//!
//! Threading: cyper's `Client` is `!Send + !Sync` (Rc-based, targets the
//! compio current_thread runtime), but the snapshotter trait requires
//! `Send` futures. All HTTP therefore runs inside `blocking::unblock`
//! on a thread-local compio runtime ([`block_on_http`]) — the same
//! pattern `storage/src/backend/connection.rs` uses for the registry
//! backend. Only `Send + Sync` state (rustls config, endpoint strings,
//! cooldown map) is held across await points.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use http::header::ACCEPT;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::config::{PeerDiscoveryMode, PeerMirrorConfig};

/// How long a peer that failed at the transport layer (refused, TLS
/// error, timeout) is skipped before we try it again. Keeps a dead node
/// from adding its full request timeout to every sidecar pull.
const PEER_COOLDOWN: Duration = Duration::from_secs(60);

/// Categorised outcome of a Spegel pull attempt for the synthetic
/// auto-accel ref. Discovery treats `NotFound` as a clean miss (no peer
/// has the sidecar — fall back to overlay) but logs `RegistryError` at
/// `warn!` so a broken mirror or stale mTLS doesn't silently disable
/// every auto-accel mount cluster-wide.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PullOutcome {
    /// Pull committed; the manifest + every referenced blob are now in
    /// the local content store and the Image record is registered.
    Ok,
    /// Every endpoint returned 404 — nobody has the content. Expected
    /// on first-pod scheduling before any node has converted.
    NotFound,
    /// A non-success, non-404 status (401/403/5xx etc), or a
    /// transport-layer failure prevented the request from completing.
    /// `status: 0` means the request never reached Spegel (transport,
    /// TLS, malformed ref, write-to-content-store failure, etc.).
    RegistryError { status: u16, body: String },
    /// Mirror is disabled by config, or the TLS material doesn't exist
    /// on disk. Quiet fallback — the locator falls through to its
    /// label-filter scan and the node behaves exactly as it did before
    /// the Spegel-pull path landed.
    Disabled,
}

/// Intermediate result for one Spegel GET (manifest or blob).
pub enum FetchResult {
    Ok(Vec<u8>),
    NotFound,
    Error {
        status: u16,
        body: String,
    },
    /// Catastrophic client-side failure that maps directly to a
    /// `PullOutcome` other than NotFound/Error.
    Outcome(PullOutcome),
}

/// Tri-state categorisation for one HTTP status code. Pulled out so unit
/// tests can pin the boundary (404 → NotFound vs 401/403/5xx → Error)
/// without spinning a real HTTP server.
fn http_status_to_outcome(status: u16) -> StatusOutcome {
    if (200..300).contains(&status) {
        StatusOutcome::Ok
    } else if status == 404 {
        StatusOutcome::NotFound
    } else {
        StatusOutcome::Error
    }
}

#[derive(Debug, Eq, PartialEq)]
enum StatusOutcome {
    Ok,
    NotFound,
    Error,
}

thread_local! {
    /// Per-thread compio runtime used by [`block_on_http`] to drive cyper
    /// from inside `blocking::unblock`. cyper's HTTPS plumbing needs
    /// `Runtime::current()` at client-build time and a `block_on` to run
    /// requests, so each blocking thread gets its own.
    static HTTP_RUNTIME: compio::runtime::Runtime = compio::runtime::Runtime::new()
        .expect("peer mirror: failed to create compio HTTP runtime");

    /// Per-thread cyper client cache, keyed by [`ClientKey`]. A fresh
    /// `cyper::Client` builds a rustls TLS config *and* a connection
    /// pool; a multi-blob sidecar pull calls [`PeerMirror::fetch`]
    /// (and `NodeDiscovery::fetch_nodes`) dozens of times in a row on
    /// the same blocking thread, so rebuilding per call was dozens of
    /// redundant TLS handshakes and pool setups. `cached_client`
    /// rebuilds only when the key changes (i.e. never in practice,
    /// since `PeerMirror` builds its `Arc<rustls::ClientConfig>` once
    /// in [`build_peer_mirror`] and holds it for its lifetime).
    static HTTP_CLIENT: RefCell<Option<(ClientKey, cyper::Client)>> = const { RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Counts real `cyper::Client` constructions on this thread — the
    /// unit tests assert this stays at 1 across repeated
    /// [`cached_client`] calls with the same key.
    static CLIENT_BUILD_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn block_on_http<F: std::future::Future>(fut: F) -> F::Output {
    HTTP_RUNTIME.with(|rt| rt.block_on(fut))
}

/// Identity key for the per-thread [`HTTP_CLIENT`] cache: which rustls
/// `ClientConfig` — or "no TLS" — a cached client was built from. The
/// `Arc<rustls::ClientConfig>` is constructed once in
/// [`build_peer_mirror`] and held for the mirror's lifetime (mirrored
/// into `NodeDiscovery`), so its identity is stable to key on; a `Client`
/// is only ever rebuilt if that identity changes (e.g. a mirror
/// reconfiguration, or a test constructing a second `PeerMirror` on the
/// same thread).
///
/// The `Tls` variant stores the `Arc` itself, not an erased pointer: the
/// cache holding the `Arc` pins the allocation so its pointer identity
/// stays valid for the cache entry's lifetime. A bare `usize` from
/// `Arc::as_ptr` would be an ABA hazard — a dropped config could free its
/// allocation, a new config could be allocated at the same address, and a
/// stale cached client would be served for it. Comparison uses
/// [`Arc::ptr_eq`], so it's still a cheap pointer compare, not a deep
/// `ClientConfig` equality.
enum ClientKey {
    Plain,
    Tls(Arc<rustls::ClientConfig>),
}

impl ClientKey {
    fn for_tls(tls: &Option<Arc<rustls::ClientConfig>>) -> Self {
        match tls {
            Some(cfg) => ClientKey::Tls(Arc::clone(cfg)),
            None => ClientKey::Plain,
        }
    }

    /// True when `self` and `other` name the same TLS config (by `Arc`
    /// identity) or are both plain-HTTP.
    fn matches(&self, other: &ClientKey) -> bool {
        match (self, other) {
            (ClientKey::Plain, ClientKey::Plain) => true,
            (ClientKey::Tls(a), ClientKey::Tls(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

/// Build a fresh cyper client. `tls: None` means plain HTTP (tests,
/// non-TLS mirrors). Only called by [`cached_client`] on a cache miss —
/// callers on the HTTP blocking thread should use `cached_client`
/// instead so the connection pool and TLS session cache survive across
/// requests.
fn build_client(tls: Option<Arc<rustls::ClientConfig>>) -> Result<cyper::Client> {
    let builder = cyper::Client::builder();
    let builder = match tls {
        Some(tls) => builder.use_rustls(tls),
        None => builder,
    };
    builder
        .build()
        .context("build cyper client for peer mirror")
}

/// Get-or-build the cyper client for the current blocking thread's
/// cache, keyed on `tls`'s identity (see [`ClientKey`]). `cyper::Client`
/// clones cheaply (an internal `Rc` shares the connection pool and TLS
/// session cache), so callers get their own handle without re-running
/// TLS setup on every call.
fn cached_client(tls: Option<Arc<rustls::ClientConfig>>) -> Result<cyper::Client> {
    let key = ClientKey::for_tls(&tls);
    HTTP_CLIENT.with(|cell| {
        if let Some((cached_key, client)) = cell.borrow().as_ref()
            && cached_key.matches(&key)
        {
            return Ok(client.clone());
        }
        let client = build_client(tls)?;
        #[cfg(test)]
        CLIENT_BUILD_COUNT.with(|c| c.set(c.get() + 1));
        *cell.borrow_mut() = Some((key, client.clone()));
        Ok(client)
    })
}

/// Peer registry mirror (k3s' embedded Spegel is the reference preset) with
/// optional automatic peer discovery and failover. Cheap to clone via `Arc`
/// by callers; internally all state is `Send + Sync`.
pub struct PeerMirror {
    /// `None` for plain-HTTP endpoints (tests, non-TLS mirrors); mTLS
    /// material for the k3s supervisor port otherwise.
    tls: Option<Arc<rustls::ClientConfig>>,
    /// The local mirror — always tried first so single-node clusters
    /// keep the cheap local hit and never touch the network.
    primary: String,
    /// Query-parameter template appended to every `/v2/...` request (the
    /// Spegel `?ns={registry}` quirk as data). Empty ⇒ no query parameter.
    query_template: String,
    /// Operator-pinned peer endpoints from config. Tried after
    /// discovered peers; kept for clusters without API access or for
    /// pinning an order in tests.
    static_peers: Vec<String>,
    /// Kubernetes node discovery. `None` when disabled by config or
    /// when TLS material is unavailable (the API needs the same mTLS).
    discovery: Option<NodeDiscovery>,
    /// Per-request timeout for one endpoint attempt.
    request_timeout: Duration,
    /// Round-robin offset so consecutive pulls spread load across peers
    /// instead of hammering the first discovered node.
    rotation: AtomicUsize,
    /// Peers that recently failed at the transport layer, mapped to the
    /// instant the failure happened. Skipped until `PEER_COOLDOWN`
    /// elapses.
    cooldown: Mutex<HashMap<String, Instant>>,
}

impl PeerMirror {
    /// Expand this mirror's query template for `registry_host`. Returns
    /// `None` when the template is empty (no query parameter appended),
    /// else the template with `{registry}` substituted. For the Spegel
    /// presets this yields `ns=<registry>`.
    pub fn artifact_query(&self, registry_host: &str) -> Option<String> {
        crate::config::expand_query_template(&self.query_template, registry_host)
    }

    /// Assemble the endpoint list for one fetch: primary, then
    /// discovered peers (rotated), then static peers; deduped, with
    /// cooled-down peers skipped (unless that would leave only the
    /// primary — a dead-peer list must not block the local hit, and a
    /// stale cooldown must not hide the only copy).
    fn endpoints_for_attempt(&self) -> Vec<String> {
        let mut endpoints = vec![self.primary.clone()];

        let mut peers: Vec<String> = Vec::new();
        if let Some(discovery) = &self.discovery {
            let discovered = discovery.peers();
            if !discovered.is_empty() {
                let offset = self.rotation.fetch_add(1, Ordering::Relaxed) % discovered.len();
                peers.extend(discovered[offset..].iter().cloned());
                peers.extend(discovered[..offset].iter().cloned());
            }
        }
        peers.extend(self.static_peers.iter().cloned());

        let now = Instant::now();
        let cooldown = self.cooldown.lock().unwrap_or_else(|e| e.into_inner());
        for peer in peers {
            if endpoints.contains(&peer) {
                continue;
            }
            if let Some(failed_at) = cooldown.get(&peer)
                && now.duration_since(*failed_at) < PEER_COOLDOWN
            {
                debug!(peer = %peer, "peer mirror: skipping cooled-down peer");
                continue;
            }
            endpoints.push(peer);
        }
        endpoints
    }

    fn mark_peer_failed(&self, endpoint: &str) {
        if endpoint == self.primary {
            // The local mirror is never cooled down — it's the cheap
            // path and its failure modes (k3s restart) self-heal.
            return;
        }
        let mut cooldown = self.cooldown.lock().unwrap_or_else(|e| e.into_inner());
        cooldown.insert(endpoint.to_string(), Instant::now());
    }

    /// GET + body read against the ordered endpoint list.
    ///
    /// Iteration rules:
    /// - 2xx from any endpoint → `Ok(bytes)`, no further endpoints tried.
    /// - 404 from one endpoint → try the next. 404 across the entire
    ///   list → `NotFound` (real "nobody has it" signal).
    /// - Any other status / transport error → remember it as a candidate
    ///   `Error` outcome but keep iterating: a peer further down the
    ///   list might still have the content. If every endpoint either
    ///   errors or 404s and at least one errored, surface the LAST error
    ///   (richest triage data for the operator).
    ///
    /// `path_and_query` MUST start with `/v2/...` and include the
    /// load-bearing `?ns=<registry>` query parameter.
    pub async fn fetch(
        self: &Arc<Self>,
        path_and_query: &str,
        accept: Option<&str>,
    ) -> FetchResult {
        let this = Arc::clone(self);
        let path = path_and_query.to_string();
        let accept = accept.map(str::to_string);
        blocking::unblock(move || {
            block_on_http(async move {
                if let Some(discovery) = &this.discovery {
                    // Refresh on this blocking thread so the gRPC runtime
                    // never waits on the Kubernetes API.
                    discovery.refresh_if_stale().await;
                }
                let client = match cached_client(this.tls.clone()) {
                    Ok(c) => c,
                    Err(e) => {
                        return FetchResult::Outcome(PullOutcome::RegistryError {
                            status: 0,
                            body: e.to_string(),
                        });
                    }
                };
                let endpoints = this.endpoints_for_attempt();
                let mut last_error: Option<FetchResult> = None;
                let mut last_outcome: Option<FetchResult> = None;
                for endpoint in &endpoints {
                    let url = format!("{endpoint}{path}");
                    debug!(target: "nydus_snapshotter::peer_mirror", url = %url, "peer mirror attempt");
                    let req_builder = match client.get(&url) {
                        Ok(r) => r,
                        Err(e) => {
                            debug!(target: "nydus_snapshotter::peer_mirror", url = %url, error = %e, "peer mirror: invalid URL");
                            last_outcome = Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                status: 0,
                                body: format!("invalid peer mirror URL {url}: {e}"),
                            }));
                            continue;
                        }
                    };
                    let req = if let Some(ref accept) = accept {
                        match req_builder.header(ACCEPT, accept.as_str()) {
                            Ok(r) => r,
                            Err(e) => {
                                last_outcome =
                                    Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                        status: 0,
                                        body: format!("invalid Accept header for {url}: {e}"),
                                    }));
                                continue;
                            }
                        }
                    } else {
                        req_builder
                    };
                    let response =
                        match compio::time::timeout(this.request_timeout, req.send()).await {
                            Ok(Ok(r)) => r,
                            Ok(Err(e)) => {
                                debug!(target: "nydus_snapshotter::peer_mirror", url = %url, error = %e, "peer mirror: transport error");
                                this.mark_peer_failed(endpoint);
                                last_outcome =
                                    Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                        status: 0,
                                        body: format!("transport error for {url}: {e}"),
                                    }));
                                continue;
                            }
                            Err(_) => {
                                debug!(target: "nydus_snapshotter::peer_mirror", url = %url, "peer mirror: request timeout");
                                this.mark_peer_failed(endpoint);
                                last_outcome =
                                    Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                        status: 0,
                                        body: format!("peer mirror request timed out for {url}"),
                                    }));
                                continue;
                            }
                        };
                    let status = response.status();
                    debug!(target: "nydus_snapshotter::peer_mirror", url = %url, status = %status, "peer mirror: response");
                    match http_status_to_outcome(status.as_u16()) {
                        StatusOutcome::Ok => match response.bytes().await {
                            Ok(b) => return FetchResult::Ok(b.to_vec()),
                            Err(e) => {
                                last_outcome =
                                    Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                        status: status.as_u16(),
                                        body: format!("read body for {url}: {e}"),
                                    }));
                            }
                        },
                        StatusOutcome::NotFound => {
                            // Try the next peer; keep going.
                        }
                        StatusOutcome::Error => {
                            let body = response.text().await.unwrap_or_default();
                            last_error = Some(FetchResult::Error {
                                status: status.as_u16(),
                                body,
                            });
                        }
                    }
                }
                // No 2xx from any endpoint. Prefer surfacing a real Error
                // (operator wants to see 5xx / TLS / transport failure)
                // over a NotFound, since NotFound is the expected
                // "nobody has it" case.
                last_error.or(last_outcome).unwrap_or(FetchResult::NotFound)
            })
        })
        .await
    }

    /// The local (primary) mirror endpoint — always tried first by
    /// [`fetch`](Self::fetch), and the only endpoint [`probe_local`](Self::probe_local)
    /// touches. Exposed for diagnostic logging (self-check).
    pub fn primary_endpoint(&self) -> &str {
        &self.primary
    }

    /// GET `path_and_query` against ONLY the local (primary) mirror endpoint —
    /// no discovered/static peer fan-out, no cooldown bookkeeping.
    ///
    /// This is the transport for the local-mirror self-check: probing a digest
    /// known to be in this node's own content store against the local mirror
    /// tells us whether the embedded registry is advertising local content.
    /// A peer answering would defeat the purpose (it says nothing about the
    /// LOCAL mirror), so the peer list is deliberately not consulted.
    ///
    /// `path_and_query` MUST start with `/v2/...` and include the load-bearing
    /// `?ns=<registry>` query parameter (see [`Self::artifact_query`]).
    pub async fn probe_local(&self, path_and_query: &str, accept: Option<&str>) -> FetchResult {
        let tls = self.tls.clone();
        let url = format!("{}{}", self.primary, path_and_query);
        let timeout = self.request_timeout;
        let accept = accept.map(str::to_string);
        blocking::unblock(move || {
            block_on_http(async move {
                let client = match cached_client(tls) {
                    Ok(c) => c,
                    Err(e) => {
                        return FetchResult::Outcome(PullOutcome::RegistryError {
                            status: 0,
                            body: e.to_string(),
                        });
                    }
                };
                let req_builder = match client.get(&url) {
                    Ok(r) => r,
                    Err(e) => {
                        return FetchResult::Outcome(PullOutcome::RegistryError {
                            status: 0,
                            body: format!("invalid local mirror URL {url}: {e}"),
                        });
                    }
                };
                let req = match accept {
                    Some(ref accept) => match req_builder.header(ACCEPT, accept.as_str()) {
                        Ok(r) => r,
                        Err(e) => {
                            return FetchResult::Outcome(PullOutcome::RegistryError {
                                status: 0,
                                body: format!("invalid Accept header for {url}: {e}"),
                            });
                        }
                    },
                    None => req_builder,
                };
                let response = match compio::time::timeout(timeout, req.send()).await {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        return FetchResult::Outcome(PullOutcome::RegistryError {
                            status: 0,
                            body: format!("transport error for {url}: {e}"),
                        });
                    }
                    Err(_) => {
                        return FetchResult::Outcome(PullOutcome::RegistryError {
                            status: 0,
                            body: format!("local mirror request timed out for {url}"),
                        });
                    }
                };
                let status = response.status();
                match http_status_to_outcome(status.as_u16()) {
                    StatusOutcome::Ok => match response.bytes().await {
                        Ok(b) => FetchResult::Ok(b.to_vec()),
                        Err(e) => FetchResult::Outcome(PullOutcome::RegistryError {
                            status: status.as_u16(),
                            body: format!("read body for {url}: {e}"),
                        }),
                    },
                    StatusOutcome::NotFound => FetchResult::NotFound,
                    StatusOutcome::Error => {
                        let body = response.text().await.unwrap_or_default();
                        FetchResult::Error {
                            status: status.as_u16(),
                            body,
                        }
                    }
                }
            })
        })
        .await
    }
}

/// Kubernetes node discovery: `GET /api/v1/nodes` on the local API
/// server using the same mTLS identity the mirror requires, cached with
/// a TTL. Each Ready node's first InternalIP becomes a peer mirror
/// endpoint `https://<ip>:<port>`; the local node is skipped.
struct NodeDiscovery {
    /// Always the local API server — node lists are identical
    /// cluster-wide and the local server answers without a network hop.
    api_endpoint: String,
    tls: Arc<rustls::ClientConfig>,
    /// Local hostname; nodes whose `metadata.name` matches are skipped
    /// (k3s node names default to the hostname).
    self_node: String,
    /// Port the mirror listens on, taken from the primary endpoint so
    /// discovered peers mirror the operator's choice.
    mirror_port: u16,
    ttl: Duration,
    cache: Mutex<DiscoveryCache>,
}

struct DiscoveryCache {
    refreshed_at: Option<Instant>,
    peers: Vec<String>,
}

impl NodeDiscovery {
    /// Cached peer list. Never blocks on the network — staleness is
    /// handled by [`refresh_if_stale`](Self::refresh_if_stale), which
    /// `PeerMirror::fetch` runs on its blocking thread before
    /// assembling endpoints.
    fn peers(&self) -> Vec<String> {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peers
            .clone()
    }

    /// Refresh the node list when the cache is older than `ttl`. Runs on
    /// the blocking pool's compio runtime (called from inside
    /// `PeerMirror::fetch`). A failed refresh keeps the previous list
    /// — a momentarily unreachable API server must not drop working
    /// peers mid-flight.
    async fn refresh_if_stale(&self) {
        {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(at) = cache.refreshed_at
                && at.elapsed() < self.ttl
            {
                return;
            }
        }
        match self.fetch_nodes().await {
            Ok(peers) => {
                let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                if cache.peers != peers {
                    info!(peers = ?peers, "peer mirror: discovered peer mirrors from kubernetes nodes");
                }
                cache.peers = peers;
                cache.refreshed_at = Some(Instant::now());
            }
            Err(e) => {
                let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                warn!(
                    error = %e,
                    stale_peers = cache.peers.len(),
                    "peer mirror: kubernetes node discovery failed; keeping previous peer list"
                );
                // Still bump the timestamp so a down API server is
                // retried once per TTL, not once per pull.
                cache.refreshed_at = Some(Instant::now());
            }
        }
    }

    async fn fetch_nodes(&self) -> Result<Vec<String>> {
        let client = cached_client(Some(self.tls.clone()))?;
        let url = format!("{}/api/v1/nodes?limit=500", self.api_endpoint);
        let request = client
            .get(&url)
            .with_context(|| format!("invalid nodes URL {url}"))?;
        let response = compio::time::timeout(Duration::from_secs(10), request.send())
            .await
            .map_err(|_| anyhow!("nodes request timed out"))?
            .with_context(|| format!("nodes request failed for {url}"))?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "nodes request returned HTTP {}",
                response.status().as_u16()
            ));
        }
        let body = response.bytes().await.context("read nodes body")?;
        let nodes: NodeList = serde_json::from_slice(&body).context("parse nodes JSON")?;
        Ok(peer_endpoints_from_nodes(
            &nodes,
            &self.self_node,
            self.mirror_port,
        ))
    }
}

/// Translate a Kubernetes NodeList into peer mirror endpoints: every
/// Ready node except `self_node`, preferring the first IPv4 InternalIP
/// (IPv6 fallback, bracketed). Pure so tests can pin the shape.
fn peer_endpoints_from_nodes(nodes: &NodeList, self_node: &str, mirror_port: u16) -> Vec<String> {
    let mut peers = Vec::new();
    for node in &nodes.items {
        if node.metadata.name == self_node {
            continue;
        }
        let ready = node
            .status
            .conditions
            .iter()
            .any(|c| c.kind == "Ready" && c.status == "True");
        if !ready {
            continue;
        }
        let internal: Vec<&str> = node
            .status
            .addresses
            .iter()
            .filter(|a| a.kind == "InternalIP")
            .map(|a| a.address.as_str())
            .collect();
        let Some(ip) = internal
            .iter()
            .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
            .or_else(|| internal.first())
        else {
            continue;
        };
        let endpoint = if ip.contains(':') {
            format!("https://[{ip}]:{mirror_port}")
        } else {
            format!("https://{ip}:{mirror_port}")
        };
        if !peers.contains(&endpoint) {
            peers.push(endpoint);
        }
    }
    peers
}

#[derive(Debug, Deserialize)]
struct NodeList {
    #[serde(default)]
    items: Vec<Node>,
}

#[derive(Debug, Deserialize)]
struct Node {
    metadata: NodeMetadata,
    status: NodeStatus,
}

#[derive(Debug, Deserialize)]
struct NodeMetadata {
    name: String,
}

#[derive(Debug, Deserialize, Default)]
struct NodeStatus {
    #[serde(default)]
    addresses: Vec<NodeAddress>,
    #[serde(default)]
    conditions: Vec<NodeCondition>,
}

#[derive(Debug, Deserialize)]
struct NodeAddress {
    #[serde(rename = "type")]
    kind: String,
    address: String,
}

#[derive(Debug, Deserialize)]
struct NodeCondition {
    #[serde(rename = "type")]
    kind: String,
    status: String,
}

/// Build the mirror handle from config. Pure metadata: no cyper client
/// is constructed here (it's `!Send`); clients are built per call on
/// blocking threads.
///
/// `Ok(None)` is returned when the mirror is disabled by config, or
/// when the endpoint is HTTPS but the TLS material doesn't exist on
/// disk — both map to "skip the Spegel-pull path" so a host without an
/// embedded mirror runs exactly as before.
pub fn build_peer_mirror(cfg: &PeerMirrorConfig) -> Result<Option<Arc<PeerMirror>>> {
    if !cfg.is_enabled() {
        return Ok(None);
    }
    let primary = cfg.endpoint().trim_end_matches('/').to_string();
    let plain_http = primary.starts_with("http://");

    // A plain-HTTP endpoint needs no client auth. An HTTPS endpoint uses mTLS
    // only when all three cert paths are configured AND present on disk;
    // otherwise the mirror is silently disabled (the pre-existing "certs
    // missing ⇒ silent fallback" contract). This lets a no-client-auth
    // plain-HTTP mirror be expressed without any k3s cert files existing.
    let tls = if plain_http {
        None
    } else {
        let (Some(ca), Some(cert), Some(key)) =
            (cfg.ca_path(), cfg.client_cert_path(), cfg.client_key_path())
        else {
            debug!(
                endpoint = %primary,
                "peer mirror TLS endpoint has no client cert material configured; mirror client disabled"
            );
            return Ok(None);
        };
        for path in [ca, cert, key] {
            if !path.is_file() {
                debug!(
                    ca = %ca.display(),
                    cert = %cert.display(),
                    key = %key.display(),
                    missing = %path.display(),
                    "peer mirror cert file missing; mirror client disabled"
                );
                return Ok(None);
            }
        }
        Some(Arc::new(build_tls_config(ca, cert, key)?))
    };

    let static_peers: Vec<String> = cfg
        .peer_endpoints
        .iter()
        .map(|p| p.trim_end_matches('/').to_string())
        .filter(|p| !p.is_empty() && *p != primary)
        .collect();

    let request_timeout = crate::cache::parse_duration(&cfg.request_timeout)
        .unwrap_or_else(|_| Duration::from_secs(10));

    let discovery = match (cfg.peer_discovery(), &tls) {
        (PeerDiscoveryMode::Kubernetes, Some(tls)) => {
            let mirror_port = primary
                .rsplit(':')
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(6443);
            let self_node = local_hostname();
            let ttl = crate::cache::parse_duration(&cfg.discovery_ttl)
                .unwrap_or_else(|_| Duration::from_secs(300));
            Some(NodeDiscovery {
                api_endpoint: primary.clone(),
                tls: tls.clone(),
                self_node,
                mirror_port,
                ttl,
                cache: Mutex::new(DiscoveryCache {
                    refreshed_at: None,
                    peers: Vec::new(),
                }),
            })
        }
        (PeerDiscoveryMode::Kubernetes, None) => {
            debug!("peer mirror discovery needs mTLS; disabled for plain-HTTP endpoint");
            None
        }
        (PeerDiscoveryMode::Static, _) | (PeerDiscoveryMode::Off, _) => None,
    };

    Ok(Some(Arc::new(PeerMirror {
        tls,
        primary,
        query_template: cfg.query_template.clone(),
        static_peers,
        discovery,
        request_timeout,
        rotation: AtomicUsize::new(0),
        cooldown: Mutex::new(HashMap::new()),
    })))
}

fn local_hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_default()
}

fn build_tls_config(
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> Result<rustls::ClientConfig> {
    // PEM loading uses rustls-pki-types' own `pem` module (re-exported as
    // `rustls::pki_types::pem`) — the same parser the archived rustls-pemfile
    // crate wrapped (RUSTSEC-2025-0134). Like its predecessor it skips PEM
    // sections of a foreign kind, hence the explicit zero-item guards below.
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem};

    // 1. Custom root CA (for k3s-spegel: the k3s server CA — system trust
    //    store is not used; the only things we authenticate are the embedded
    //    Spegel mirrors and the API server, all signed by this CA).
    let mut roots = rustls::RootCertStore::empty();
    let ca_certs = CertificateDer::pem_file_iter(ca_path)
        .with_context(|| format!("open peer mirror CA cert {}", ca_path.display()))?;
    let mut ca_added = 0usize;
    for cert in ca_certs {
        let cert =
            cert.with_context(|| format!("parse peer mirror CA cert {}", ca_path.display()))?;
        roots
            .add(cert)
            .with_context(|| format!("add peer mirror CA to root store {}", ca_path.display()))?;
        ca_added += 1;
    }
    if ca_added == 0 {
        return Err(anyhow!("no CA certificates found in {}", ca_path.display()));
    }

    // 2. Client identity for mTLS (for k3s-spegel: the k3s controller cert +
    //    key — same identity k3s' own internal components use).
    let client_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(client_cert_path)
            .with_context(|| {
                format!(
                    "open peer mirror client cert {}",
                    client_cert_path.display()
                )
            })?
            .collect::<std::result::Result<_, _>>()
            .with_context(|| {
                format!(
                    "parse peer mirror client cert {}",
                    client_cert_path.display()
                )
            })?;
    if client_certs.is_empty() {
        return Err(anyhow!(
            "no client certificates found in {}",
            client_cert_path.display()
        ));
    }

    // Accepts the first PKCS#8 / SEC1 / PKCS#1 key section, skipping others.
    let client_key = match PrivateKeyDer::from_pem_file(client_key_path) {
        Ok(key) => key,
        Err(pem::Error::NoItemsFound) => {
            return Err(anyhow!(
                "no private key found in {}",
                client_key_path.display()
            ));
        }
        Err(pem::Error::Io(e)) => {
            return Err(e).with_context(|| {
                format!("open peer mirror client key {}", client_key_path.display())
            });
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!("parse peer mirror client key {}", client_key_path.display())
            });
        }
    };

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, client_key)
        .context("build rustls ClientConfig for peer mirror")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `http_status_to_outcome` decides whether Spegel's response is a
    /// clean "no peer has it" (silent fallback to overlay) or a real
    /// "mirror is broken" signal that needs operator attention.
    #[test]
    fn http_status_404_is_not_found() {
        assert_eq!(http_status_to_outcome(404), StatusOutcome::NotFound);
    }

    #[test]
    fn http_status_2xx_is_ok() {
        assert_eq!(http_status_to_outcome(200), StatusOutcome::Ok);
        assert_eq!(http_status_to_outcome(204), StatusOutcome::Ok);
        assert_eq!(http_status_to_outcome(299), StatusOutcome::Ok);
    }

    #[test]
    fn http_status_auth_failures_are_error() {
        // 401/403 → Spegel mTLS misconfigured, client cert expired, etc.
        // Operator needs the signal — NOT a silent fallback.
        assert_eq!(http_status_to_outcome(401), StatusOutcome::Error);
        assert_eq!(http_status_to_outcome(403), StatusOutcome::Error);
    }

    #[test]
    fn http_status_5xx_is_error() {
        assert_eq!(http_status_to_outcome(500), StatusOutcome::Error);
        assert_eq!(http_status_to_outcome(502), StatusOutcome::Error);
        assert_eq!(http_status_to_outcome(503), StatusOutcome::Error);
    }

    #[test]
    fn http_status_3xx_is_error() {
        // We don't follow redirects through Spegel — a peer that needs
        // to redirect us is a config bug to flag.
        assert_eq!(http_status_to_outcome(301), StatusOutcome::Error);
        assert_eq!(http_status_to_outcome(307), StatusOutcome::Error);
    }

    fn node(name: &str, ips: &[&str], ready: bool) -> Node {
        Node {
            metadata: NodeMetadata {
                name: name.to_string(),
            },
            status: NodeStatus {
                addresses: ips
                    .iter()
                    .map(|ip| NodeAddress {
                        kind: "InternalIP".to_string(),
                        address: ip.to_string(),
                    })
                    .collect(),
                conditions: vec![NodeCondition {
                    kind: "Ready".to_string(),
                    status: if ready { "True" } else { "False" }.to_string(),
                }],
            },
        }
    }

    /// The node-list translation is the contract that replaces the
    /// manual `peer_endpoints` config. Pin: self-exclusion, Ready
    /// filtering, IPv4 preference over IPv6, IPv6 bracketing.
    #[test]
    fn peer_endpoints_skip_self_and_not_ready() {
        let nodes = NodeList {
            items: vec![
                node("self", &["192.168.1.10"], true),
                node("peer-a", &["192.168.1.11"], true),
                node("peer-down", &["192.168.1.12"], false),
            ],
        };
        let peers = peer_endpoints_from_nodes(&nodes, "self", 6443);
        assert_eq!(peers, vec!["https://192.168.1.11:6443"]);
    }

    #[test]
    fn peer_endpoints_prefer_ipv4_over_ipv6() {
        let nodes = NodeList {
            items: vec![node("peer-a", &["fd00:1234:5678::1", "192.168.1.11"], true)],
        };
        let peers = peer_endpoints_from_nodes(&nodes, "self", 6443);
        assert_eq!(peers, vec!["https://192.168.1.11:6443"]);
    }

    #[test]
    fn peer_endpoints_bracket_ipv6_only_nodes() {
        let nodes = NodeList {
            items: vec![node("peer-a", &["fd00:1234:5678::1"], true)],
        };
        let peers = peer_endpoints_from_nodes(&nodes, "self", 6443);
        assert_eq!(peers, vec!["https://[fd00:1234:5678::1]:6443"]);
    }

    #[test]
    fn peer_endpoints_respect_mirror_port() {
        let nodes = NodeList {
            items: vec![node("peer-a", &["192.168.1.11"], true)],
        };
        let peers = peer_endpoints_from_nodes(&nodes, "self", 7443);
        assert_eq!(peers, vec!["https://192.168.1.11:7443"]);
    }

    /// The NodeList serde shape must match the live API — this fixture
    /// is a trimmed real response from `GET /api/v1/nodes`.
    #[test]
    fn node_list_parses_real_api_shape() {
        let body = r#"{
            "kind": "NodeList",
            "items": [{
                "metadata": {"name": "node-b", "labels": {"x": "y"}},
                "status": {
                    "addresses": [
                        {"type": "InternalIP", "address": "10.0.0.8"},
                        {"type": "InternalIP", "address": "fd00:1234:5678::1"},
                        {"type": "Hostname", "address": "node-b"}
                    ],
                    "conditions": [
                        {"type": "MemoryPressure", "status": "False"},
                        {"type": "Ready", "status": "True"}
                    ]
                }
            }]
        }"#;
        let nodes: NodeList = serde_json::from_slice(body.as_bytes()).unwrap();
        let peers = peer_endpoints_from_nodes(&nodes, "elsewhere", 6443);
        assert_eq!(peers, vec!["https://10.0.0.8:6443"]);
    }

    fn test_mirror(primary: &str, static_peers: &[&str]) -> Arc<PeerMirror> {
        Arc::new(PeerMirror {
            tls: None,
            primary: primary.to_string(),
            query_template: "ns={registry}".to_string(),
            static_peers: static_peers.iter().map(|s| s.to_string()).collect(),
            discovery: None,
            request_timeout: Duration::from_secs(2),
            rotation: AtomicUsize::new(0),
            cooldown: Mutex::new(HashMap::new()),
        })
    }

    /// `artifact_query` expands the mirror's template with the registry host;
    /// the default `ns={registry}` yields Spegel's load-bearing `?ns=` param.
    #[test]
    fn artifact_query_expands_ns_template() {
        let mirror = test_mirror("http://127.0.0.1:1", &[]);
        assert_eq!(
            mirror.artifact_query("registry.example:5000"),
            Some("ns=registry.example:5000".to_string())
        );
    }

    /// Endpoint assembly: primary always first, static peers after,
    /// duplicates of the primary dropped.
    #[test]
    fn endpoints_primary_first_then_peers_deduped() {
        let mirror = test_mirror(
            "http://127.0.0.1:1",
            &["http://peer-a:1", "http://127.0.0.1:1", "http://peer-b:1"],
        );
        // NOTE: build_peer_mirror dedupes primary from static_peers at
        // construction; endpoints_for_attempt dedupes again defensively.
        let endpoints = mirror.endpoints_for_attempt();
        assert_eq!(
            endpoints,
            vec!["http://127.0.0.1:1", "http://peer-a:1", "http://peer-b:1"]
        );
    }

    /// A transport-failed peer is skipped while cooled down; the primary
    /// never cools down.
    #[test]
    fn cooled_down_peer_is_skipped_but_primary_never() {
        let mirror = test_mirror(
            "http://127.0.0.1:1",
            &["http://peer-a:1", "http://peer-b:1"],
        );
        mirror.mark_peer_failed("http://peer-a:1");
        mirror.mark_peer_failed("http://127.0.0.1:1");
        let endpoints = mirror.endpoints_for_attempt();
        assert_eq!(endpoints, vec!["http://127.0.0.1:1", "http://peer-b:1"]);
    }

    /// Minimal, cert-file-free rustls config for keying the client
    /// cache — the process-default `CryptoProvider` (rustls' `ring`
    /// cargo feature; see workspace `Cargo.toml`) is auto-installed on
    /// first use, so no explicit `install_default()` is needed here.
    fn dummy_tls_config() -> Arc<rustls::ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    /// Repeated [`cached_client`] calls on the same thread with the same
    /// TLS identity must reuse one `cyper::Client` (pool + TLS session
    /// cache), not rebuild per call — that rebuild was the whole
    /// perf bug this cache fixes.
    #[test]
    fn cached_client_reused_for_same_tls_key() {
        block_on_http(async {
            CLIENT_BUILD_COUNT.with(|c| c.set(0));
            let tls = dummy_tls_config();
            for _ in 0..5 {
                cached_client(Some(tls.clone())).expect("build cached client");
            }
            assert_eq!(
                CLIENT_BUILD_COUNT.with(|c| c.get()),
                1,
                "client should only be built once for a stable TLS identity"
            );
        });
    }

    /// A `None` (plain-HTTP) key is likewise cached and distinct from
    /// any TLS-backed client.
    #[test]
    fn cached_client_reused_for_plain_http() {
        block_on_http(async {
            CLIENT_BUILD_COUNT.with(|c| c.set(0));
            for _ in 0..3 {
                cached_client(None).expect("build cached plain client");
            }
            assert_eq!(CLIENT_BUILD_COUNT.with(|c| c.get()), 1);
        });
    }

    /// A change in TLS config identity (e.g. a test/caller building a
    /// second `PeerMirror` on the same thread with different TLS
    /// material) must evict the cached client and rebuild rather than
    /// silently reusing a client built for a different config.
    #[test]
    fn cached_client_rebuilds_when_tls_key_changes() {
        block_on_http(async {
            CLIENT_BUILD_COUNT.with(|c| c.set(0));
            let tls_a = dummy_tls_config();
            let tls_b = dummy_tls_config();
            cached_client(Some(tls_a.clone())).expect("build client a");
            cached_client(Some(tls_a)).expect("reuse client a");
            cached_client(Some(tls_b)).expect("build client b");
            assert_eq!(
                CLIENT_BUILD_COUNT.with(|c| c.get()),
                2,
                "distinct TLS identities must each build exactly one client"
            );
        });
    }

    // ---- build_tls_config: PEM identity loading ----
    //
    // Throwaway test-only identity (EC P-256, CN=nydus-peer-mirror-test,
    // self-signed, valid to 2046). The certificate and the two key
    // encodings below are the SAME key pair — `with_client_auth_cert`
    // parses the key through the ring provider, so the material must be
    // genuine. Never use this key outside this test module.
    const TEST_CERT_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIBljCCAT2gAwIBAgIUH2CY6EpcCSul24kgqnvRpR867GAwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWbnlkdXMtcGVlci1taXJyb3ItdGVzdDAeFw0yNjA3MTUwMDQ1
NDFaFw00NjA3MTAwMDQ1NDFaMCExHzAdBgNVBAMMFm55ZHVzLXBlZXItbWlycm9y
LXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR6ofTJvnpenmDK8aFi8wcE
GvWJ03vGhxeVcetw/dA4TnmDJDPwl26sgyeAe4VzdC7cuFJZ6wKt3mmp3Ic4V0oZ
o1MwUTAdBgNVHQ4EFgQU0PD3NalGUUvozo7afVumnT+IWNwwHwYDVR0jBBgwFoAU
0PD3NalGUUvozo7afVumnT+IWNwwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD
AgNHADBEAiA3gE3QTKdoVKS3mxs9cuZIWjc8o1fZDOzU1bYmKlJtygIgUmvFA6jX
TPkOLsyiOpBJ239612rqvYAon3DdwuFIUmU=
-----END CERTIFICATE-----
";

    const TEST_KEY_PKCS8_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJSaYyR0ouMeKF3wM
x8xv+rg7G61cn2v6UynFoLQqhQ2hRANCAAR6ofTJvnpenmDK8aFi8wcEGvWJ03vG
hxeVcetw/dA4TnmDJDPwl26sgyeAe4VzdC7cuFJZ6wKt3mmp3Ic4V0oZ
-----END PRIVATE KEY-----
";

    const TEST_KEY_SEC1_PEM: &str = r"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICUmmMkdKLjHihd8DMfMb/q4OxutXJ9r+lMpxaC0KoUNoAoGCCqGSM49
AwEHoUQDQgAEeqH0yb56Xp5gyvGhYvMHBBr1idN7xocXlXHrcP3QOE55gyQz8Jdu
rIMngHuFc3Qu3LhSWesCrd5pqdyHOFdKGQ==
-----END EC PRIVATE KEY-----
";

    fn write_pem(dir: &tempfile::TempDir, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("write test PEM");
        path
    }

    /// Happy path: CA + client cert + PKCS#8 key yield an mTLS
    /// `ClientConfig`. Pins the loader's accepted-input contract so the
    /// PEM-parsing internals can be swapped under green tests.
    #[test]
    fn tls_config_loads_valid_ca_cert_and_pkcs8_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = write_pem(&dir, "ca.pem", TEST_CERT_PEM);
        let cert = write_pem(&dir, "client.pem", TEST_CERT_PEM);
        let key = write_pem(&dir, "client.key", TEST_KEY_PKCS8_PEM);
        build_tls_config(&ca, &cert, &key).expect("valid PEM identity must load");
    }

    /// k3s writes its client keys in SEC1 (`EC PRIVATE KEY`) form as
    /// well — the loader must accept all standard plaintext key
    /// encodings (PKCS#8 above, SEC1 here), not just one.
    #[test]
    fn tls_config_accepts_sec1_ec_client_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = write_pem(&dir, "ca.pem", TEST_CERT_PEM);
        let cert = write_pem(&dir, "client.pem", TEST_CERT_PEM);
        let key = write_pem(&dir, "client.key", TEST_KEY_SEC1_PEM);
        build_tls_config(&ca, &cert, &key).expect("SEC1 EC key must load");
    }

    /// Foreign PEM sections (a stray key in a CA bundle) are skipped,
    /// not fatal — the cert after them must still be found.
    #[test]
    fn tls_config_skips_foreign_pem_sections_in_ca_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = format!("{TEST_KEY_PKCS8_PEM}{TEST_CERT_PEM}");
        let ca = write_pem(&dir, "ca.pem", &bundle);
        let cert = write_pem(&dir, "client.pem", TEST_CERT_PEM);
        let key = write_pem(&dir, "client.key", TEST_KEY_PKCS8_PEM);
        build_tls_config(&ca, &cert, &key).expect("cert after foreign sections must load");
    }

    /// An empty CA file must hard-error: silently trusting nothing would
    /// disable peer authentication instead of failing loudly.
    #[test]
    fn tls_config_rejects_empty_ca_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = write_pem(&dir, "ca.pem", "");
        let cert = write_pem(&dir, "client.pem", TEST_CERT_PEM);
        let key = write_pem(&dir, "client.key", TEST_KEY_PKCS8_PEM);
        let err = build_tls_config(&ca, &cert, &key).expect_err("empty CA file must be rejected");
        assert!(
            err.to_string().contains("no CA certificates found"),
            "unexpected error: {err:#}"
        );
    }

    /// A CA file whose only PEM section is a private key holds zero
    /// certificates — the skip-foreign-sections behavior must not let it
    /// silently satisfy the CA load.
    #[test]
    fn tls_config_rejects_ca_file_without_certificates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = write_pem(&dir, "ca.pem", TEST_KEY_PKCS8_PEM);
        let cert = write_pem(&dir, "client.pem", TEST_CERT_PEM);
        let key = write_pem(&dir, "client.key", TEST_KEY_PKCS8_PEM);
        let err = build_tls_config(&ca, &cert, &key).expect_err("cert-free CA file rejected");
        assert!(
            err.to_string().contains("no CA certificates found"),
            "unexpected error: {err:#}"
        );
    }

    /// Same guard for the client certificate chain.
    #[test]
    fn tls_config_rejects_client_cert_file_without_certificates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = write_pem(&dir, "ca.pem", TEST_CERT_PEM);
        let cert = write_pem(&dir, "client.pem", TEST_KEY_PKCS8_PEM);
        let key = write_pem(&dir, "client.key", TEST_KEY_PKCS8_PEM);
        let err = build_tls_config(&ca, &cert, &key).expect_err("cert-free client file rejected");
        assert!(
            err.to_string().contains("no client certificates found"),
            "unexpected error: {err:#}"
        );
    }

    /// A key file whose only PEM section is a certificate contains no
    /// usable private key and must be rejected with the dedicated
    /// missing-key message.
    #[test]
    fn tls_config_rejects_key_file_without_private_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = write_pem(&dir, "ca.pem", TEST_CERT_PEM);
        let cert = write_pem(&dir, "client.pem", TEST_CERT_PEM);
        let key = write_pem(&dir, "client.key", TEST_CERT_PEM);
        let err = build_tls_config(&ca, &cert, &key).expect_err("key-free key file rejected");
        assert!(
            err.to_string().contains("no private key found"),
            "unexpected error: {err:#}"
        );
    }

    /// Malformed PEM (a section that never ends) is a parse error, never
    /// a silent success.
    #[test]
    fn tls_config_rejects_malformed_ca_pem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = write_pem(&dir, "ca.pem", "-----BEGIN CERTIFICATE-----\nzzzz\n");
        let cert = write_pem(&dir, "client.pem", TEST_CERT_PEM);
        let key = write_pem(&dir, "client.key", TEST_KEY_PKCS8_PEM);
        let err = build_tls_config(&ca, &cert, &key).expect_err("malformed CA PEM rejected");
        assert!(
            err.to_string().contains("CA cert"),
            "unexpected error: {err:#}"
        );
    }

    /// A missing CA file surfaces as an open error naming the path, so
    /// the operator sees which of the three PEM paths is wrong.
    #[test]
    fn tls_config_reports_missing_ca_file_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = dir.path().join("does-not-exist.pem");
        let cert = write_pem(&dir, "client.pem", TEST_CERT_PEM);
        let key = write_pem(&dir, "client.key", TEST_KEY_PKCS8_PEM);
        let err = build_tls_config(&ca, &cert, &key).expect_err("missing CA file rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("open peer mirror CA cert") && msg.contains("does-not-exist.pem"),
            "unexpected error: {err:#}"
        );
    }
}
