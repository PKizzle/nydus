// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! HTTP client for k3s' embedded spegel registry mirror, with automatic
//! peer discovery.
//!
//! The auto-accel consumer pulls sidecar artifacts through spegel's
//! distribution endpoint (`/v2/...?ns=<registry>` — the `ns` query
//! parameter is load-bearing; without it spegel's distribution.go parser
//! 404s every path). Spegel's own cross-node routing relies on a libp2p
//! DHT whose provider-address records rot on long-lived clusters (the
//! k3s-bundled spegel v0.7.x serves "could not find peer" /
//! "empty list of address ports" for content that peers demonstrably
//! hold), so this module bypasses libp2p entirely: it discovers the
//! cluster's node IPs from the Kubernetes API — using the same mTLS
//! identity the mirror endpoint already requires — and walks each peer's
//! mirror endpoint directly.
//!
//! Failover semantics live in [`SpegelMirror::fetch`]: primary (local
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

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use http::header::ACCEPT;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::config::{PeerDiscoveryMode, SpegelMirrorConfig};

/// How long a peer that failed at the transport layer (refused, TLS
/// error, timeout) is skipped before we try it again. Keeps a dead node
/// from adding its full request timeout to every sidecar pull.
const PEER_COOLDOWN: Duration = Duration::from_secs(60);

/// Categorised outcome of a spegel pull attempt for the synthetic
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
    /// `status: 0` means the request never reached spegel (transport,
    /// TLS, malformed ref, write-to-content-store failure, etc.).
    RegistryError { status: u16, body: String },
    /// Mirror is disabled by config, or the TLS material doesn't exist
    /// on disk. Quiet fallback — the locator falls through to its
    /// label-filter scan and the node behaves exactly as it did before
    /// the spegel-pull path landed.
    Disabled,
}

/// Intermediate result for one spegel GET (manifest or blob).
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
        .expect("spegel: failed to create compio HTTP runtime");
}

fn block_on_http<F: std::future::Future>(fut: F) -> F::Output {
    HTTP_RUNTIME.with(|rt| rt.block_on(fut))
}

/// Build a one-shot cyper client for the current blocking thread.
/// `tls: None` means plain HTTP (tests, non-TLS mirrors).
fn build_client(tls: Option<Arc<rustls::ClientConfig>>) -> Result<cyper::Client> {
    let builder = cyper::Client::builder();
    let builder = match tls {
        Some(tls) => builder.use_rustls(tls),
        None => builder,
    };
    builder.build().context("build cyper client for spegel")
}

/// k3s embedded spegel mirror with automatic peer discovery and
/// failover. Cheap to clone via `Arc` by callers; internally all state
/// is `Send + Sync`.
pub struct SpegelMirror {
    /// `None` for plain-HTTP endpoints (tests, non-TLS mirrors); mTLS
    /// material for the k3s supervisor port otherwise.
    tls: Option<Arc<rustls::ClientConfig>>,
    /// The local mirror — always tried first so single-node clusters
    /// keep the cheap local hit and never touch the network.
    primary: String,
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

impl SpegelMirror {
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
                debug!(peer = %peer, "spegel: skipping cooled-down peer");
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
                let client = match build_client(this.tls.clone()) {
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
                    debug!(target: "nydus_snapshotter::spegel", url = %url, "spegel attempt");
                    let req_builder = match client.get(&url) {
                        Ok(r) => r,
                        Err(e) => {
                            debug!(target: "nydus_snapshotter::spegel", url = %url, error = %e, "spegel: invalid URL");
                            last_outcome = Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                status: 0,
                                body: format!("invalid spegel URL {url}: {e}"),
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
                                debug!(target: "nydus_snapshotter::spegel", url = %url, error = %e, "spegel: transport error");
                                this.mark_peer_failed(endpoint);
                                last_outcome =
                                    Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                        status: 0,
                                        body: format!("transport error for {url}: {e}"),
                                    }));
                                continue;
                            }
                            Err(_) => {
                                debug!(target: "nydus_snapshotter::spegel", url = %url, "spegel: request timeout");
                                this.mark_peer_failed(endpoint);
                                last_outcome =
                                    Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                        status: 0,
                                        body: format!("spegel request timed out for {url}"),
                                    }));
                                continue;
                            }
                        };
                    let status = response.status();
                    debug!(target: "nydus_snapshotter::spegel", url = %url, status = %status, "spegel: response");
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
    /// `SpegelMirror::fetch` runs on its blocking thread before
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
    /// `SpegelMirror::fetch`). A failed refresh keeps the previous list
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
                    info!(peers = ?peers, "spegel: discovered peer mirrors from kubernetes nodes");
                }
                cache.peers = peers;
                cache.refreshed_at = Some(Instant::now());
            }
            Err(e) => {
                let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                warn!(
                    error = %e,
                    stale_peers = cache.peers.len(),
                    "spegel: kubernetes node discovery failed; keeping previous peer list"
                );
                // Still bump the timestamp so a down API server is
                // retried once per TTL, not once per pull.
                cache.refreshed_at = Some(Instant::now());
            }
        }
    }

    async fn fetch_nodes(&self) -> Result<Vec<String>> {
        let client = build_client(Some(self.tls.clone()))?;
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
/// disk — both map to "skip the spegel-pull path" so a host without an
/// embedded mirror runs exactly as before.
pub fn build_spegel_mirror(cfg: &SpegelMirrorConfig) -> Result<Option<Arc<SpegelMirror>>> {
    if !cfg.enable {
        return Ok(None);
    }
    let primary = cfg.endpoint.trim_end_matches('/').to_string();
    let plain_http = primary.starts_with("http://");

    let tls = if plain_http {
        None
    } else {
        for path in [&cfg.ca_path, &cfg.client_cert_path, &cfg.client_key_path] {
            if !path.is_file() {
                debug!(
                    ca = %cfg.ca_path.display(),
                    cert = %cfg.client_cert_path.display(),
                    key = %cfg.client_key_path.display(),
                    missing = %path.display(),
                    "spegel cert file missing; mirror client disabled"
                );
                return Ok(None);
            }
        }
        Some(Arc::new(build_tls_config(cfg)?))
    };

    let static_peers: Vec<String> = cfg
        .peer_endpoints
        .iter()
        .map(|p| p.trim_end_matches('/').to_string())
        .filter(|p| !p.is_empty() && *p != primary)
        .collect();

    let request_timeout = crate::cache::parse_duration(&cfg.request_timeout)
        .unwrap_or_else(|_| Duration::from_secs(10));

    let discovery = match (&cfg.peer_discovery, &tls) {
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
            debug!("spegel peer discovery needs mTLS; disabled for plain-HTTP endpoint");
            None
        }
        (PeerDiscoveryMode::Static, _) | (PeerDiscoveryMode::Off, _) => None,
    };

    Ok(Some(Arc::new(SpegelMirror {
        tls,
        primary,
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

fn build_tls_config(cfg: &SpegelMirrorConfig) -> Result<rustls::ClientConfig> {
    // 1. Custom root CA (the k3s server CA — system trust store is not
    //    used; the only things we authenticate are the embedded spegel
    //    mirrors and the API server, all signed by this CA).
    let mut roots = rustls::RootCertStore::empty();
    let mut ca_reader = BufReader::new(
        File::open(&cfg.ca_path)
            .with_context(|| format!("open spegel CA cert {}", cfg.ca_path.display()))?,
    );
    let mut ca_added = 0usize;
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        let cert =
            cert.with_context(|| format!("parse spegel CA cert {}", cfg.ca_path.display()))?;
        roots
            .add(cert)
            .with_context(|| format!("add spegel CA to root store {}", cfg.ca_path.display()))?;
        ca_added += 1;
    }
    if ca_added == 0 {
        return Err(anyhow!(
            "no CA certificates found in {}",
            cfg.ca_path.display()
        ));
    }

    // 2. Client identity for mTLS (k3s controller cert + key — same
    //    identity k3s' own internal components use).
    let mut cert_reader =
        BufReader::new(File::open(&cfg.client_cert_path).with_context(|| {
            format!("open spegel client cert {}", cfg.client_cert_path.display())
        })?);
    let client_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<_, _>>()
            .with_context(|| {
                format!(
                    "parse spegel client cert {}",
                    cfg.client_cert_path.display()
                )
            })?;
    if client_certs.is_empty() {
        return Err(anyhow!(
            "no client certificates found in {}",
            cfg.client_cert_path.display()
        ));
    }

    let mut key_reader =
        BufReader::new(File::open(&cfg.client_key_path).with_context(|| {
            format!("open spegel client key {}", cfg.client_key_path.display())
        })?);
    let client_key = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("parse spegel client key {}", cfg.client_key_path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", cfg.client_key_path.display()))?;

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, client_key)
        .context("build rustls ClientConfig for spegel mirror")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `http_status_to_outcome` decides whether spegel's response is a
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
        // 401/403 → spegel mTLS misconfigured, client cert expired, etc.
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
        // We don't follow redirects through spegel — a peer that needs
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

    fn test_mirror(primary: &str, static_peers: &[&str]) -> Arc<SpegelMirror> {
        Arc::new(SpegelMirror {
            tls: None,
            primary: primary.to_string(),
            static_peers: static_peers.iter().map(|s| s.to_string()).collect(),
            discovery: None,
            request_timeout: Duration::from_secs(2),
            rotation: AtomicUsize::new(0),
            cooldown: Mutex::new(HashMap::new()),
        })
    }

    /// Endpoint assembly: primary always first, static peers after,
    /// duplicates of the primary dropped.
    #[test]
    fn endpoints_primary_first_then_peers_deduped() {
        let mirror = test_mirror(
            "http://127.0.0.1:1",
            &["http://peer-a:1", "http://127.0.0.1:1", "http://peer-b:1"],
        );
        // NOTE: build_spegel_mirror dedupes primary from static_peers at
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
}
