// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Unified TOML configuration for the Nydus snapshotter.
//!
//! A single `config.toml` replaces the former separate snapshotter TOML +
//! nydusd JSON pair. Storage backends are declared inline under `[backends.*]`
//! sections. Filesystem drivers default to automatic best-available selection;
//! operators can set `fs_driver_policy = "ordered"` to preserve an explicit
//! `[[snapshotter.fs_drivers]]` fallback chain.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level configuration loaded from `/etc/nydus/config.toml`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SnapshotterConfig {
    // `#[serde(default)]` so a config with no `[snapshotter]` table at all
    // (e.g. one that only sets `[backends.registry]`, or an empty file) still
    // parses: every field inside `SnapshotterSection` already has a serde
    // default and the section has a `Default` impl.
    #[serde(default)]
    pub snapshotter: SnapshotterSection,
    #[serde(default, rename = "backends")]
    pub backends: BackendsConfig,
}

/// `[snapshotter]` section.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SnapshotterSection {
    /// Deployment profile. Fills host-path defaults (containerd socket +
    /// content-store root) and the peer-mirror preset when those fields are
    /// left unset. `auto` (the default) probes the well-known containerd
    /// sockets at startup; `k3s` / `containerd` pin the profile explicitly.
    /// Explicit TOML values for the profile-sensitive fields always win over
    /// the profile table — see [`SnapshotterConfig::resolve_profile`].
    #[serde(default)]
    pub profile: Profile,
    /// Root directory for snapshotter state (default `/var/lib/containerd-nydus`).
    #[serde(default = "default_root")]
    pub root: PathBuf,
    /// Address for the containerd gRPC proxy socket.
    #[serde(default = "default_address")]
    pub address: PathBuf,
    /// Clean up state on graceful shutdown.
    #[serde(default)]
    pub cleanup_on_close: bool,

    #[serde(default)]
    pub daemon: DaemonConfig,

    /// Filesystem driver selection policy. The default is `auto`, which ranks
    /// the configured drivers by built-in performance preference before probing.
    /// Use `ordered` to preserve the exact TOML order as an operator override.
    #[serde(default)]
    pub fs_driver_policy: FsDriverSelectionPolicy,

    /// Candidate filesystem drivers. In `auto` mode this is a candidate set;
    /// in `ordered` mode it is an explicit fallback chain.
    /// First probed entry that succeeds becomes the active driver.
    #[serde(default = "default_fs_drivers")]
    pub fs_drivers: Vec<FsDriverEntry>,

    #[serde(default)]
    pub cache: CacheConfig,

    #[serde(default)]
    pub recon: ReconConfig,

    #[serde(default)]
    pub sysctl: SysctlConfig,

    /// Optional Prometheus metrics listener. By default (no `[snapshotter.metrics]`
    /// section, `listen = None`) metrics are exposed only over the sysctl UDS
    /// `GET /metrics` endpoint; setting `listen` additionally binds a TCP
    /// `GET /metrics` HTTP endpoint (parity with the Go snapshotter's TCP metrics).
    #[serde(default)]
    pub metrics: MetricsConfig,

    #[serde(default)]
    pub features: FeaturesConfig,

    /// Tarfs driver options (dm-verity, subprocess tool paths). Only consulted
    /// when the tarfs driver actually serves an image.
    #[serde(default)]
    pub tarfs: TarfsConfig,

    #[serde(default)]
    pub cgroup: CgroupConfig,

    /// Background node-local zran conversion for plain OCI images, triggered
    /// by file-access traces captured during pod startup.
    #[serde(default)]
    pub auto_zran: AutoZranConfig,

    /// Containerd integration (Content gRPC client, content-store layout).
    /// Required when `auto_zran.enable = true` so the snapshotter can read
    /// gzip-layer blobs and upload sidecar artifacts.
    #[serde(default)]
    pub containerd: ContainerdConfig,

    /// Peer registry-mirror endpoint used by auto-accel cross-node sidecar
    /// discovery. When enabled and reachable, a peer-node consumer can fetch
    /// the OCI manifest + config + blobs for a converted sidecar straight
    /// from the mirror's `/v2/...` endpoint rather than each node having to
    /// convert independently. k3s' embedded Spegel is the reference preset;
    /// see [`PeerMirrorConfig`]. Accepts the legacy `[snapshotter.spegel_mirror]`
    /// table name via serde alias for back-compat.
    #[serde(default, alias = "spegel_mirror")]
    pub peer_mirror: PeerMirrorConfig,
}

impl Default for SnapshotterSection {
    fn default() -> Self {
        Self {
            profile: Profile::default(),
            root: default_root(),
            address: default_address(),
            cleanup_on_close: false,
            daemon: DaemonConfig::default(),
            fs_driver_policy: FsDriverSelectionPolicy::default(),
            fs_drivers: default_fs_drivers(),
            cache: CacheConfig::default(),
            recon: ReconConfig::default(),
            sysctl: SysctlConfig::default(),
            metrics: MetricsConfig::default(),
            features: FeaturesConfig::default(),
            tarfs: TarfsConfig::default(),
            cgroup: CgroupConfig::default(),
            auto_zran: AutoZranConfig::default(),
            containerd: ContainerdConfig::default(),
            peer_mirror: PeerMirrorConfig::default(),
        }
    }
}

/// Deployment profile controlling host-path defaults (containerd socket +
/// content-store root) and the peer-mirror preset. Only fills fields the
/// operator left unset; explicit TOML values always win.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Probe the well-known containerd sockets at startup and pick k3s or
    /// stock-containerd accordingly (default).
    #[default]
    Auto,
    /// k3s: `/run/k3s/containerd/containerd.sock`, k3s content-store root,
    /// k3s-spegel peer-mirror preset.
    K3s,
    /// Stock containerd: `/run/containerd/containerd.sock`, standard content
    /// root, no peer-mirror preset.
    Containerd,
}

/// The concrete host-path + preset table a resolved [`Profile`] selects.
/// `Profile::Auto` never appears here — it resolves to `K3s` or `Containerd`
/// first.
struct ProfileDefaults {
    containerd_address: PathBuf,
    content_root: PathBuf,
    mirror_preset: MirrorPreset,
}

impl Profile {
    /// Host-path + preset table for a concrete (non-`Auto`) profile. `Auto`
    /// is treated as `Containerd` here as a defensive fallback, but callers
    /// resolve `Auto` before reaching this.
    fn defaults(self) -> ProfileDefaults {
        match self {
            Profile::K3s => ProfileDefaults {
                containerd_address: PathBuf::from(K3S_CONTAINERD_SOCKET),
                content_root: PathBuf::from(K3S_CONTENT_ROOT),
                mirror_preset: MirrorPreset::K3sSpegel,
            },
            Profile::Auto | Profile::Containerd => ProfileDefaults {
                containerd_address: PathBuf::from(STOCK_CONTAINERD_SOCKET),
                content_root: PathBuf::from(STOCK_CONTENT_ROOT),
                mirror_preset: MirrorPreset::None,
            },
        }
    }
}

/// Well-known containerd socket probed for `Profile::Auto` k3s detection.
pub const K3S_CONTAINERD_SOCKET: &str = "/run/k3s/containerd/containerd.sock";
/// Well-known containerd socket probed for `Profile::Auto` stock detection.
pub const STOCK_CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";
/// Boot-stable k3s installation artifacts, probed when neither socket exists
/// yet. Standard unit ordering starts the proxy snapshotter BEFORE
/// containerd/k3s (containerd waits for the snapshotter's socket), so on a
/// clean boot the socket probes see nothing — these paths survive reboots and
/// identify a k3s node regardless of service start order.
pub const K3S_DATA_DIR: &str = "/var/lib/rancher/k3s";
/// See [`K3S_DATA_DIR`]; `/etc/rancher/k3s` holds the k3s config and is
/// likewise boot-stable.
pub const K3S_ETC_DIR: &str = "/etc/rancher/k3s";
/// k3s content-store root (profile default + nothing else — no accessor
/// fallback uses it, but kept next to its socket for symmetry).
pub const K3S_CONTENT_ROOT: &str =
    "/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content";
/// Stock-containerd content-store root. Used by both the containerd profile
/// table AND the `ContainerdConfig::content_root` accessor fallback — keep
/// them referencing this one const so they can never drift apart.
pub const STOCK_CONTENT_ROOT: &str = "/var/lib/containerd/io.containerd.content.v1.content";
/// Default local peer-mirror endpoint (k3s' embedded Spegel binds here).
/// Used by every `MirrorPreset` table AND the `PeerMirrorConfig::endpoint`
/// accessor fallback — one source of truth for both.
pub const DEFAULT_MIRROR_ENDPOINT: &str = "https://127.0.0.1:6443";

/// Outcome of profile resolution: the concrete profile chosen and a
/// human-readable reason (logged at `info!` by the binary).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProfile {
    pub profile: Profile,
    pub reason: String,
}

impl SnapshotterConfig {
    /// Resolve `[snapshotter].profile` in memory and fill any profile- or
    /// preset-sensitive field the operator left unset. NEVER writes config
    /// files — it only mutates the parsed struct. Run this after config load
    /// + CLI overrides and before the driver probe / `DaemonSupervisor`.
    ///
    /// Explicit TOML values always win: a field that deserialised to `Some`
    /// (or an explicit preset/discovery) is left untouched; only `None`
    /// fields are filled from the resolved profile / preset table.
    pub fn resolve_profile(&mut self) -> Result<ResolvedProfile, ConfigError> {
        self.resolve_profile_with(|p: &std::path::Path| p.exists())
    }

    /// [`resolve_profile`](Self::resolve_profile) with an injectable socket
    /// probe so unit tests never touch the real filesystem.
    pub fn resolve_profile_with(
        &mut self,
        probe: impl Fn(&std::path::Path) -> bool,
    ) -> Result<ResolvedProfile, ConfigError> {
        let auto_zran_enabled = self.snapshotter.auto_zran.enable;
        let resolved = match self.snapshotter.profile {
            Profile::K3s => ResolvedProfile {
                profile: Profile::K3s,
                reason: "profile = k3s set explicitly".to_string(),
            },
            Profile::Containerd => ResolvedProfile {
                profile: Profile::Containerd,
                reason: "profile = containerd set explicitly".to_string(),
            },
            Profile::Auto => {
                let k3s = probe(std::path::Path::new(K3S_CONTAINERD_SOCKET));
                let stock = probe(std::path::Path::new(STOCK_CONTAINERD_SOCKET));
                match (k3s, stock) {
                    (true, true) => {
                        return Err(ConfigError::AmbiguousProfile);
                    }
                    (true, false) => ResolvedProfile {
                        profile: Profile::K3s,
                        reason: format!("auto-detected k3s ({K3S_CONTAINERD_SOCKET} present)"),
                    },
                    (false, true) => ResolvedProfile {
                        profile: Profile::Containerd,
                        reason: format!(
                            "auto-detected containerd ({STOCK_CONTAINERD_SOCKET} present)"
                        ),
                    },
                    (false, false) => {
                        // Clean-boot ordering: the snapshotter usually starts
                        // before containerd/k3s, so missing sockets do NOT
                        // mean "not a k3s node". Check boot-stable k3s
                        // installation artifacts before defaulting — silently
                        // resolving a k3s node to `containerd` loses the
                        // content root and disables the peer-mirror preset on
                        // every boot.
                        let k3s_installed = probe(std::path::Path::new(K3S_DATA_DIR))
                            || probe(std::path::Path::new(K3S_ETC_DIR));
                        if k3s_installed {
                            ResolvedProfile {
                                profile: Profile::K3s,
                                reason: format!(
                                    "auto-detected k3s ({K3S_DATA_DIR} present; no containerd \
                                     socket yet — snapshotter started before k3s)"
                                ),
                            }
                        } else if auto_zran_enabled {
                            return Err(ConfigError::NoContainerdSocket);
                        } else {
                            tracing::warn!(
                                "profile = auto found no containerd socket and no k3s \
                                 installation; defaulting to the `containerd` profile. If this \
                                 is wrong, set [snapshotter].profile explicitly."
                            );
                            ResolvedProfile {
                                profile: Profile::Containerd,
                                reason: "no containerd socket or k3s installation detected; \
                                         defaulting to containerd (auto_zran disabled)"
                                    .to_string(),
                            }
                        }
                    }
                }
            }
        };

        let table = resolved.profile.defaults();

        // Host-path defaults (containerd socket + content root). Explicit
        // values stay untouched.
        let containerd = &mut self.snapshotter.containerd;
        if containerd.address.is_none() {
            containerd.address = Some(table.containerd_address.clone());
        }
        if containerd.content_root.is_none() {
            containerd.content_root = Some(table.content_root.clone());
        }

        // Peer-mirror preset (profile-derived when unset) then the
        // preset-derived mirror fields.
        let pm = &mut self.snapshotter.peer_mirror;
        let preset = pm.preset.unwrap_or(table.mirror_preset);
        pm.preset = Some(preset);
        let mdef = preset.defaults();
        if pm.enable.is_none() {
            pm.enable = Some(mdef.enable);
        }
        if pm.endpoint.is_none() {
            pm.endpoint = Some(mdef.endpoint);
        }
        if pm.peer_discovery.is_none() {
            pm.peer_discovery = Some(mdef.peer_discovery);
        }
        if pm.ca_path.is_none() {
            pm.ca_path = mdef.ca_path;
        }
        if pm.client_cert_path.is_none() {
            pm.client_cert_path = mdef.client_cert_path;
        }
        if pm.client_key_path.is_none() {
            pm.client_key_path = mdef.client_key_path;
        }

        // Exhaustiveness guard. The destructures below name every field, so
        // adding a new profile-sensitive `Option` to either struct and
        // forgetting its fill line above fails to COMPILE here (missing-field
        // error), not silently at runtime. The `debug_assert!`s then pin the
        // invariant that the unconditionally-filled fields are `Some` after
        // resolution — a forgotten fill would otherwise leave `None`, the
        // accessor would fall back to the stock default, and k3s would get the
        // wrong value with no compile error and no test failure.
        let ContainerdConfig {
            address,
            namespace: _,
            content_root,
        } = &self.snapshotter.containerd;
        debug_assert!(
            address.is_some() && content_root.is_some(),
            "resolve_profile left a containerd host-path field unset: \
             address={address:?} content_root={content_root:?}"
        );
        let PeerMirrorConfig {
            preset,
            enable,
            endpoint,
            peer_discovery,
            // Cert paths are preset-derived and legitimately `None` for the
            // `spegel`/`none` presets, so they are named (to catch a
            // rename/removal) but NOT asserted `Some`.
            ca_path: _,
            client_cert_path: _,
            client_key_path: _,
            // Non-profile-sensitive fields carry plain serde defaults; named
            // only to keep this destructure exhaustive.
            query_template: _,
            discovery_ttl: _,
            request_timeout: _,
            peer_endpoints: _,
        } = &self.snapshotter.peer_mirror;
        debug_assert!(
            preset.is_some() && enable.is_some() && endpoint.is_some() && peer_discovery.is_some(),
            "resolve_profile left a preset-derived mirror field unset: \
             preset={preset:?} enable={enable:?} endpoint={endpoint:?} \
             peer_discovery={peer_discovery:?}"
        );

        Ok(resolved)
    }
}

/// Errors from [`SnapshotterConfig::resolve_profile`]. Kept as a typed error
/// so the binary can print an actionable, kubeadm-style message.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "both k3s ({K3S_CONTAINERD_SOCKET}) and containerd ({STOCK_CONTAINERD_SOCKET}) \
         sockets are present; profile detection is ambiguous. Set `profile` explicitly \
         in [snapshotter] (profile = \"k3s\" or profile = \"containerd\")."
    )]
    AmbiguousProfile,
    #[error(
        "no containerd socket found at {K3S_CONTAINERD_SOCKET} or {STOCK_CONTAINERD_SOCKET}, \
         but auto_zran is enabled and needs one. Start containerd/k3s, or set \
         [snapshotter.containerd].address and [snapshotter].profile explicitly."
    )]
    NoContainerdSocket,
    #[error(
        "[backends.localfs] is configured but the localfs backend is reserved for the \
         internal node-local acceleration (auto-accel) sidecar path and is not a pull \
         backend the in-process daemon honours. Use [backends.registry], [backends.s3], \
         [backends.oss], or [backends.http_proxy], or remove this section."
    )]
    LocalFsNotAPullBackend,
    #[error(
        "multiple pull backends are configured ({configured}); exactly one of \
         [backends.registry], [backends.s3], [backends.oss], [backends.http_proxy] may \
         drive the daemon. Remove the extra section(s)."
    )]
    MultiplePullBackends { configured: String },
}

/// Daemon lifecycle configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DaemonConfig {
    /// Recovery policy: "none", "restart", or "failover" (default "failover").
    #[serde(default = "default_recover_policy")]
    pub recover_policy: String,
    /// Number of worker threads for the daemon runtime.
    #[serde(default = "default_threads")]
    pub threads: usize,
    /// Log level: "trace", "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Also log to stdout.
    #[serde(default)]
    pub log_to_stdout: bool,
    /// Warn when this many fds are parked in systemd's fd store. The unit's
    /// `FileDescriptorStoreMax` bounds the store, and past it systemd silently
    /// drops FDSTORE messages — failover then quietly stops arming for new
    /// daemons. Keep this a little below the unit's limit (default 96 against
    /// the documented `FileDescriptorStoreMax=128`). 0 disables the warning.
    #[serde(default = "default_fdstore_warn_threshold")]
    pub fdstore_warn_threshold: usize,
}

/// Reconciler cadence and mount-health probing (`[snapshotter.recon]`).
///
/// The reconciler's cheap self-healing passes (daemon recovery, orphan-mount
/// scan, stale-dir sweeps, mount-health probing) tick at `period`; the
/// expensive passes (cache GC, auto-zran sweep, sidecar GC — each enumerates
/// images or walks the cache tree) stay on the `[snapshotter.cache]`
/// `gc_period` cadence.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReconConfig {
    /// Tick interval for the cheap reconciliation passes (default "5m").
    #[serde(default = "default_recon_period")]
    pub period: String,
    /// Probe each live daemon mountpoint for health every tick and export the
    /// result as metrics + `GET /api/v1/mounts/health` (default true).
    #[serde(default = "default_true")]
    pub mount_probe: bool,
    /// Per-mount probe timeout: a FUSE mount that cannot answer a readdir
    /// within this window is reported dead (default "2s").
    #[serde(default = "default_mount_probe_timeout")]
    pub mount_probe_timeout: String,
}

impl Default for ReconConfig {
    fn default() -> Self {
        Self {
            period: default_recon_period(),
            mount_probe: true,
            mount_probe_timeout: default_mount_probe_timeout(),
        }
    }
}

/// A single entry in the `[[snapshotter.fs_drivers]]` ordered list.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FsDriverEntry {
    /// Driver type: "fanotify", "fusedev", or "blockdev".
    #[serde(rename = "type")]
    pub driver_type: FsDriverType,
    /// Minimum kernel version required (semver string, e.g. "6.14").
    /// Only checked for fanotify.
    #[serde(default)]
    pub min_kernel: Option<String>,
    /// Linux capabilities required (e.g. "CAP_SYS_ADMIN").
    #[serde(default)]
    pub require_caps: Vec<String>,
    /// Block device mode when type == "blockdev": "loop", "nbd", or "uffd".
    #[serde(default)]
    pub mode: Option<String>,
}

/// Supported filesystem driver types.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FsDriverType {
    Fanotify,
    Fusedev,
    Blockdev,
    /// Kernel-only tarfs read path: the RAFS v6 bootstrap is exported to a flat
    /// EROFS `.disk` in 512-byte tarfs mode (auto-detected from the bootstrap's
    /// `TARTFS_MODE` flag) and mounted directly by the kernel EROFS driver,
    /// optionally behind dm-verity. Distinct from `Blockdev` only in that it is
    /// the integrity-oriented path (dm-verity on by default) and its data blob
    /// is the original uncompressed tar. Opt-in: never auto-selected ahead of
    /// fanotify — reached via explicit config or the per-image
    /// `containerd.io/snapshot/nydus-fs-driver = "tarfs"` label.
    Tarfs,
}

impl FsDriverType {
    /// The lowercase driver name (matches the serde representation).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fanotify => "fanotify",
            Self::Fusedev => "fusedev",
            Self::Blockdev => "blockdev",
            Self::Tarfs => "tarfs",
        }
    }

    /// Parse the value of the per-image `containerd.io/snapshot/nydus-fs-driver`
    /// label (case-insensitive) into a driver override, or `None` if it names
    /// no known driver.
    pub fn from_hint(hint: &str) -> Option<Self> {
        match hint.trim().to_ascii_lowercase().as_str() {
            "fanotify" => Some(Self::Fanotify),
            "fusedev" => Some(Self::Fusedev),
            "blockdev" => Some(Self::Blockdev),
            "tarfs" => Some(Self::Tarfs),
            _ => None,
        }
    }
}

/// How the snapshotter chooses among configured filesystem driver candidates.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FsDriverSelectionPolicy {
    /// Rank candidates by Nydus' production preference, then probe and pick the
    /// first available driver.
    #[default]
    Auto,
    /// Preserve the configured TOML order exactly.
    Ordered,
}

/// Cache configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Working directory for blob cache files.
    #[serde(default = "default_cache_work_dir")]
    pub work_dir: PathBuf,
    /// Garbage collection period (e.g. "24h").
    #[serde(default = "default_gc_period")]
    pub gc_period: String,
    /// Maximum age for cache artifacts before they become GC candidates (e.g. "168h").
    #[serde(default)]
    pub gc_max_age: Option<String>,
    /// Maximum cache size in bytes. Oldest artifacts are evicted first.
    #[serde(default)]
    pub gc_max_bytes: Option<u64>,
    /// Report GC candidates without deleting files.
    #[serde(default)]
    pub gc_dry_run: bool,
    /// Disable indexed blob caching.
    #[serde(default)]
    pub disable_indexed: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            work_dir: default_cache_work_dir(),
            gc_period: default_gc_period(),
            gc_max_age: None,
            gc_max_bytes: None,
            gc_dry_run: false,
            disable_indexed: false,
        }
    }
}

/// System-controller API configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SysctlConfig {
    /// Enable the Unix-socket HTTP system-controller API.
    #[serde(default = "default_true")]
    pub enable: bool,
    /// Unix socket address for the system-controller API.
    #[serde(default = "default_sysctl_address")]
    pub address: PathBuf,
}

impl Default for SysctlConfig {
    fn default() -> Self {
        Self {
            enable: true,
            address: default_sysctl_address(),
        }
    }
}

/// Optional TCP Prometheus metrics listener configuration.
///
/// Additive and opt-in: with no `[snapshotter.metrics]` section `listen` is
/// `None` and the snapshotter behaves exactly as before — metrics are served
/// only over the sysctl UDS `GET /metrics` endpoint. Setting `listen` (e.g.
/// `"127.0.0.1:9110"`) additionally binds a TCP `GET /metrics` HTTP endpoint
/// that reuses the same `SnapshotterMetrics` rendering, restoring parity with
/// the Go snapshotter's TCP metrics endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// TCP socket address to bind the Prometheus `GET /metrics` endpoint on.
    /// `None` (the default) means no TCP listener — UDS-only, today's behavior.
    #[serde(default)]
    pub listen: Option<String>,
}

/// Feature flags.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeaturesConfig {
    /// Detect *published* nydus images via the OCI referrers API (the
    /// referrer-artifact distribution model nydusify / the Go snapshotter
    /// produce).
    ///
    /// ON by default. Serving is implemented (B4b) and e2e-verified: on a
    /// `Prepare` for a published nydus image the snapshotter fetches and
    /// sha256-verifies the bootstrap and mounts the daemon via the shared
    /// `ensure_instance` path (nydusd's registry backend then serves data blobs
    /// on demand). Every step is best-effort and NON-FATAL — any detection /
    /// fetch / mount error falls through to plain overlay, so a pod is never
    /// blocked, and results are cached. Set to `false` to disable referrer
    /// probing entirely.
    #[serde(default = "default_true")]
    pub referrer_detect: bool,
    #[serde(default)]
    pub encryption: bool,
    #[serde(default = "default_true")]
    pub prefetch: bool,
    #[serde(default = "default_true")]
    pub metrics: bool,
    #[serde(default)]
    pub erofs_page_cache_sharing: bool,
}

impl Default for FeaturesConfig {
    fn default() -> Self {
        // Match the serde field defaults so `FeaturesConfig::default()` (used by
        // `SnapshotterConfig::default()`) and an omitted `[snapshotter.features]`
        // table agree: referrer detection, prefetch, and metrics all default ON.
        Self {
            referrer_detect: true,
            encryption: false,
            prefetch: true,
            metrics: true,
            erofs_page_cache_sharing: false,
        }
    }
}

/// `[snapshotter.tarfs]` — options for the tarfs (dm-verity block) driver.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TarfsConfig {
    /// Generate and activate a dm-verity mapping over the exported EROFS image.
    /// Default **on**: cryptographically-verified read-only integrity is the
    /// reason to choose tarfs over the plain blockdev driver. When off, tarfs
    /// falls back to a plain kernel-loop EROFS mount of the `.disk` (still
    /// 512-byte tarfs mode, just without block-level integrity).
    #[serde(default = "default_true")]
    pub verity: bool,
    /// Path to the `veritysetup` binary used to activate the dm-verity mapping.
    #[serde(default = "default_veritysetup_path")]
    pub veritysetup_path: PathBuf,
    /// Path to the `losetup` binary used to attach the `.disk` to a loop device
    /// (dm-verity needs a block device, not a file, as its data device).
    #[serde(default = "default_losetup_path")]
    pub losetup_path: PathBuf,
}

fn default_veritysetup_path() -> PathBuf {
    PathBuf::from("veritysetup")
}
fn default_losetup_path() -> PathBuf {
    PathBuf::from("losetup")
}

impl Default for TarfsConfig {
    fn default() -> Self {
        Self {
            verity: true,
            veritysetup_path: default_veritysetup_path(),
            losetup_path: default_losetup_path(),
        }
    }
}

/// Cgroup configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CgroupConfig {
    /// Enable cgroup resource limits.
    #[serde(default)]
    pub enable: bool,
    /// Memory limit (e.g. "1Gi").
    #[serde(default)]
    pub memory_limit: Option<String>,
}

/// Background node-local zran conversion configuration.
///
/// When enabled, the access tracer captures file-access traces during pod
/// startup; on settle the snapshotter runs `local_accel::convert` to build a
/// RAFS v6 + zran artifact node-locally and uploads it to containerd's content
/// store with labels linking it to the original image manifest. Spegel then
/// mirrors the artifact to peer nodes. The original image manifest is never
/// rewritten (no tag change, no sha256 churn). Disabled by default.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutoZranConfig {
    /// Enable automatic node-local zran artifact generation. When `false`, the
    /// access tracer is also dormant and the snapshotter behaves as before.
    #[serde(default)]
    pub enable: bool,
    /// Path to the `nydus-image` binary used by `local_accel::convert` for the
    /// `create --type targz-ref` / `merge` / `optimize` invocations.
    #[serde(default = "default_auto_zran_nydus_image")]
    pub nydus_image: PathBuf,
    /// Maximum queued conversion jobs before new profiles are dropped.
    #[serde(default = "default_auto_zran_queue_depth")]
    pub queue_depth: usize,
    /// Unix niceness for conversion subprocesses. Higher means lower CPU priority.
    #[serde(default = "default_auto_zran_nice")]
    pub nice: i32,
    /// OS-portable I/O scheduling class for conversion subprocesses. `idle`
    /// uses `ionice -c 3` on Linux and `taskpolicy -c utility` on macOS;
    /// `normal` runs without explicit scheduling override.
    #[serde(default)]
    pub sched_class: SchedClass,
    /// Working directory used by node-local conversions. Per-image scratch
    /// dirs are removed after the artifacts are committed to the content store.
    #[serde(default = "default_auto_zran_work_dir")]
    pub work_dir: PathBuf,
    /// File-access capture (tracing) configuration. Tied to `enable`.
    #[serde(default)]
    pub capture: AccessCaptureConfig,
}

impl Default for AutoZranConfig {
    fn default() -> Self {
        Self {
            enable: false,
            nydus_image: default_auto_zran_nydus_image(),
            queue_depth: default_auto_zran_queue_depth(),
            nice: default_auto_zran_nice(),
            sched_class: SchedClass::default(),
            work_dir: default_auto_zran_work_dir(),
            capture: AccessCaptureConfig::default(),
        }
    }
}

/// OS-portable I/O scheduling class for low-priority background work.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SchedClass {
    /// Idle: Linux `ionice -c 3`, macOS `taskpolicy -c utility`. Default.
    #[default]
    Idle,
    /// No explicit scheduling override (run at the parent process's class).
    Normal,
}

/// File-access capture configuration for the auto-accel access tracer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessCaptureConfig {
    /// Enable the fanotify-based access tracer. Inherits from
    /// `AutoZranConfig::enable` if not explicitly set.
    #[serde(default = "default_true")]
    pub enable: bool,
    /// Idle settle threshold: stop capturing when no new files have been
    /// recorded for this duration. Default `5s`.
    #[serde(default = "default_capture_settle_idle")]
    pub settle_idle: String,
    /// Absolute capture deadline: stop capturing after this elapsed time even
    /// if reads are still ongoing. Default `60s`.
    #[serde(default = "default_capture_settle_max")]
    pub settle_max: String,
    /// Minimum number of distinct files required to submit a profile.
    /// Smaller-than-min profiles are dropped (next pod restart re-captures).
    #[serde(default = "default_capture_min_files")]
    pub min_files: usize,
    /// Safety cap on the captured file list.
    #[serde(default = "default_capture_max_files")]
    pub max_files: usize,
    /// Glob patterns excluded from the captured profile (pseudo filesystems,
    /// host bind mounts, etc.).
    #[serde(default = "default_capture_exclude_globs")]
    pub exclude_globs: Vec<String>,
}

impl Default for AccessCaptureConfig {
    fn default() -> Self {
        Self {
            enable: true,
            settle_idle: default_capture_settle_idle(),
            settle_max: default_capture_settle_max(),
            min_files: default_capture_min_files(),
            max_files: default_capture_max_files(),
            exclude_globs: default_capture_exclude_globs(),
        }
    }
}

/// Containerd integration configuration.
///
/// The snapshotter uses containerd's Content gRPC service to read gzip-layer
/// blobs (during conversion) and to upload sidecar artifacts (after
/// conversion). It also resolves blob digests to on-disk paths under
/// `content_root` so the fanotify backend dir can symlink to them without
/// re-copying.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContainerdConfig {
    /// Path to containerd's gRPC socket. Profile-sensitive: `None` when the
    /// operator didn't set it, filled from the resolved profile by
    /// [`SnapshotterConfig::resolve_profile`]. Read via [`Self::address`].
    #[serde(default)]
    pub address: Option<PathBuf>,
    /// Containerd namespace to operate in. For k3s/CRI this is `k8s.io`.
    #[serde(default = "default_containerd_namespace")]
    pub namespace: String,
    /// Root of containerd's content store on disk. Used for `blob_path`
    /// resolution (so we can pass already-committed blobs into the fanotify
    /// backend dir as symlinks). The well-known layout is stable across
    /// containerd 1.x and 2.x: `<root>/blobs/sha256/<hex>`. Profile-sensitive
    /// like `address`; read via [`Self::content_root`].
    #[serde(default)]
    pub content_root: Option<PathBuf>,
}

impl Default for ContainerdConfig {
    fn default() -> Self {
        Self {
            address: None,
            namespace: default_containerd_namespace(),
            content_root: None,
        }
    }
}

impl ContainerdConfig {
    /// Resolved containerd socket path. Falls back to the stock-containerd
    /// socket when unresolved (i.e. `resolve_profile` wasn't run), which is
    /// the safe generic default.
    pub fn address(&self) -> PathBuf {
        self.address
            .clone()
            .unwrap_or_else(|| PathBuf::from(STOCK_CONTAINERD_SOCKET))
    }

    /// Resolved content-store root. Falls back to the stock-containerd layout
    /// when unresolved.
    pub fn content_root(&self) -> PathBuf {
        self.content_root
            .clone()
            .unwrap_or_else(|| PathBuf::from(STOCK_CONTENT_ROOT))
    }
}

/// Peer registry-mirror endpoint configuration for cross-node auto-accel
/// sidecar discovery. A peer mirror watches containerd image-store events,
/// serves locally-present content over `/v2/...`, and (for Spegel) falls
/// back to libp2p peer lookup for digests it doesn't have. The consumer-side
/// `SidecarLocator::resolve_or_pull` hits this endpoint with the mirror's
/// [`query_template`](Self::query_template) query parameter appended.
///
/// k3s' embedded Spegel is the reference implementation and ships as the
/// `k3s-spegel` [`MirrorPreset`]: it binds the API-server socket on
/// `127.0.0.1:6443`, requires mTLS, and needs the load-bearing `?ns=<registry>`
/// query (without it Spegel's distribution.go parser 404s every path). Other
/// mirrors can be expressed by overriding `preset`, `endpoint`,
/// `query_template`, and the auth fields.
///
/// The profile/preset-sensitive fields are `Option`: `None` means "operator
/// didn't set it", filled from the resolved preset by
/// [`SnapshotterConfig::resolve_profile`]. Read them via the accessor methods.
///
/// When the mirror is disabled, or the endpoint is HTTPS but the configured
/// cert files don't exist on disk at startup, the pull path is skipped
/// silently and the locator falls straight through to the existing
/// label-filter scan, preserving the behaviour on hosts without a mirror.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PeerMirrorConfig {
    /// Mirror preset. `None` (the serde default) means "unset" — filled from
    /// the resolved profile (k3s ⇒ `k3s-spegel`, containerd ⇒ `none`) by
    /// `resolve_profile`. An explicit value overrides the profile default.
    #[serde(default)]
    pub preset: Option<MirrorPreset>,
    /// Whether the peer-mirror pull path is enabled. Preset-derived when unset.
    #[serde(default)]
    pub enable: Option<bool>,
    /// Mirror endpoint URL. Preset-derived when unset. k3s' embedded Spegel
    /// binds to the API-server socket on `127.0.0.1:6443`; the `/v2/...`
    /// distribution endpoints hang off the same TLS listener.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Query parameter appended to every `/v2/...` request, with `{registry}`
    /// expanded to the target registry host. Spegel's load-bearing `?ns=`
    /// quirk is expressed as the default template `ns={registry}`; an empty
    /// string means "no query parameter". See [`Self::artifact_query`].
    ///
    /// NOTE: unlike the preset-derived fields, this is a single GLOBAL default
    /// (`ns={registry}`) applied to ALL presets including `spegel` and `none` —
    /// it is not preset-sensitive and `resolve_profile` never touches it. A
    /// generic (non-Spegel) mirror under `preset = "none"` that does not want
    /// the `?ns=` parameter must set `query_template = ""` explicitly.
    #[serde(default = "default_query_template")]
    pub query_template: String,
    /// How peer mirror endpoints are found when the local mirror misses.
    /// Preset-derived when unset: every preset now defaults to `off`
    /// (local-mirror-only + native Spegel libp2p routing). `kubernetes` node
    /// fan-out remains an explicit operator opt-in — a documented resilience
    /// fallback for Spegel DHT rot, see [`crate::peer_mirror`].
    #[serde(default)]
    pub peer_discovery: Option<PeerDiscoveryMode>,
    /// How long a discovered node list is cached before it is refreshed
    /// from the API server. Refreshes run on the pull path's blocking
    /// thread, never on the snapshotter's gRPC runtime.
    #[serde(default = "default_peer_mirror_discovery_ttl")]
    pub discovery_ttl: String,
    /// Per-endpoint timeout for one mirror request. Sidecar artifacts are
    /// small (bootstrap ≈ 1 MiB, indexes ≈ KiBs), so keep this short — a
    /// slow peer must not stall pod creation.
    #[serde(default = "default_peer_mirror_request_timeout")]
    pub request_timeout: String,
    /// Statically-pinned peer mirror endpoints, tried after discovered
    /// peers (or alone with `peer_discovery = "static"`). Useful for
    /// clusters where the snapshotter may not list nodes, or to pin an
    /// order in tests. Example: `["https://node-b.internal:6443"]`.
    #[serde(default)]
    pub peer_endpoints: Vec<String>,
    /// PEM-encoded CA bundle for verifying the mirror endpoint's serving
    /// cert. Preset-derived when unset (k3s cert path only for `k3s-spegel`).
    /// `None` on a non-k3s preset means "no client auth / plain HTTP" unless
    /// the operator supplies one.
    #[serde(default)]
    pub ca_path: Option<PathBuf>,
    /// PEM-encoded client cert for mTLS to the mirror. Preset-derived when
    /// unset. k3s' standard controller client cert works for `k3s-spegel` —
    /// the same identity its own internal components use.
    #[serde(default)]
    pub client_cert_path: Option<PathBuf>,
    /// PEM-encoded private key matching `client_cert_path`. Preset-derived
    /// when unset.
    #[serde(default)]
    pub client_key_path: Option<PathBuf>,
}

impl PeerMirrorConfig {
    /// Whether the peer-mirror pull path is enabled. Defaults to disabled
    /// when unresolved (safe generic — silent fallback to the label scan).
    pub fn is_enabled(&self) -> bool {
        self.enable.unwrap_or(false)
    }

    /// Resolved mirror endpoint URL. Falls back to the local Spegel endpoint
    /// when unresolved.
    pub fn endpoint(&self) -> &str {
        self.endpoint.as_deref().unwrap_or(DEFAULT_MIRROR_ENDPOINT)
    }

    /// Resolved peer-discovery mode. Defaults to `off` (local-mirror-only)
    /// when unresolved.
    pub fn peer_discovery(&self) -> PeerDiscoveryMode {
        self.peer_discovery.unwrap_or(PeerDiscoveryMode::Off)
    }

    /// CA cert path, if configured/resolved.
    pub fn ca_path(&self) -> Option<&std::path::Path> {
        self.ca_path.as_deref()
    }

    /// Client cert path, if configured/resolved.
    pub fn client_cert_path(&self) -> Option<&std::path::Path> {
        self.client_cert_path.as_deref()
    }

    /// Client key path, if configured/resolved.
    pub fn client_key_path(&self) -> Option<&std::path::Path> {
        self.client_key_path.as_deref()
    }

    /// Expand [`query_template`](Self::query_template) for `registry_host`.
    /// Returns `None` for an empty template (no query parameter), otherwise
    /// the template with every `{registry}` occurrence substituted.
    pub fn artifact_query(&self, registry_host: &str) -> Option<String> {
        expand_query_template(&self.query_template, registry_host)
    }
}

/// Expand a mirror query template: `None` for empty, else `{registry}` →
/// `registry_host`. Pure so unit tests pin the Spegel `ns=` behaviour.
pub fn expand_query_template(template: &str, registry_host: &str) -> Option<String> {
    if template.is_empty() {
        return None;
    }
    Some(template.replace("{registry}", registry_host))
}

/// A named peer-mirror preset. Bundles the Spegel-specific quirks (endpoint,
/// mTLS cert paths, discovery mode) as data so a mirror is configured by
/// naming a preset rather than hard-coding behaviour.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum MirrorPreset {
    /// k3s' embedded Spegel: `https://127.0.0.1:6443`, mTLS with the k3s agent
    /// cert paths, and `off` peer discovery (native Spegel libp2p routing).
    /// Set `peer_discovery = "kubernetes"` explicitly to re-enable the node
    /// fan-out resilience fallback.
    K3sSpegel,
    /// Generic Spegel: local `https://127.0.0.1:6443` endpoint, `?ns=` query,
    /// but no k3s cert paths and no peer discovery (local-mirror-only). The
    /// operator supplies auth material / discovery if needed.
    Spegel,
    /// No preset: the mirror is disabled unless the operator sets `enable`
    /// and an `endpoint`. Local-mirror-only, no discovery, no default certs.
    None,
}

/// Resolved preset defaults for the mirror fields.
struct MirrorPresetDefaults {
    enable: bool,
    endpoint: String,
    peer_discovery: PeerDiscoveryMode,
    ca_path: Option<PathBuf>,
    client_cert_path: Option<PathBuf>,
    client_key_path: Option<PathBuf>,
}

impl MirrorPreset {
    fn defaults(self) -> MirrorPresetDefaults {
        match self {
            MirrorPreset::K3sSpegel => MirrorPresetDefaults {
                enable: true,
                endpoint: DEFAULT_MIRROR_ENDPOINT.to_string(),
                // Default OFF: native Spegel routing (v0.7.1+) is verified
                // working, so the local mirror + libp2p peer lookup is the
                // primary path. `kubernetes` node fan-out stays available as an
                // explicit operator opt-in resilience fallback (see
                // [`crate::peer_mirror`]); it is scheduled for removal after a
                // production soak of default-off.
                peer_discovery: PeerDiscoveryMode::Off,
                ca_path: Some(PathBuf::from("/var/lib/rancher/k3s/agent/server-ca.crt")),
                client_cert_path: Some(PathBuf::from(
                    "/var/lib/rancher/k3s/agent/client-k3s-controller.crt",
                )),
                client_key_path: Some(PathBuf::from(
                    "/var/lib/rancher/k3s/agent/client-k3s-controller.key",
                )),
            },
            MirrorPreset::Spegel => MirrorPresetDefaults {
                enable: true,
                endpoint: DEFAULT_MIRROR_ENDPOINT.to_string(),
                peer_discovery: PeerDiscoveryMode::Off,
                ca_path: None,
                client_cert_path: None,
                client_key_path: None,
            },
            MirrorPreset::None => MirrorPresetDefaults {
                enable: false,
                endpoint: DEFAULT_MIRROR_ENDPOINT.to_string(),
                peer_discovery: PeerDiscoveryMode::Off,
                ca_path: None,
                client_cert_path: None,
                client_key_path: None,
            },
        }
    }
}

/// Where the peer-mirror pull path finds peer mirror endpoints.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PeerDiscoveryMode {
    /// List the cluster's nodes from the local Kubernetes API server and
    /// try each Ready node's mirror endpoint. Documented Spegel-DHT-rot
    /// resilience fallback; opt-in only (no preset defaults to it any more).
    Kubernetes,
    /// No peers — only the local mirror endpoint is tried. The default
    /// discovery mode for every preset.
    #[default]
    Off,
    /// Only the statically-configured `peer_endpoints`.
    Static,
}

/// All backend sections under `[backends.*]`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BackendsConfig {
    #[serde(default)]
    pub registry: Option<RegistryBackendConfig>,
    #[serde(default)]
    pub s3: Option<S3BackendConfig>,
    #[serde(default)]
    pub oss: Option<OssBackendConfig>,
    #[serde(default)]
    pub localfs: Option<LocalFsBackendConfig>,
    #[serde(default)]
    pub http_proxy: Option<HttpProxyBackendConfig>,
}

impl BackendsConfig {
    /// The `type` strings of the configured pull backends, in a stable order.
    /// Everything except `localfs` (which is reserved for the auto-accel
    /// sidecar path — see [`crate::daemon::config_builder`]). An empty result
    /// means "no explicit pull backend": the daemon defaults to the image's
    /// own registry.
    pub fn pull_backends(&self) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        if self.registry.is_some() {
            kinds.push("registry");
        }
        if self.s3.is_some() {
            kinds.push("s3");
        }
        if self.oss.is_some() {
            kinds.push("oss");
        }
        if self.http_proxy.is_some() {
            kinds.push("http-proxy");
        }
        kinds
    }

    /// Reject backend configurations the in-process daemon cannot honour,
    /// turning what used to be a silent no-op into an actionable startup error:
    ///
    /// - `[backends.localfs]` is reserved for the auto-accel sidecar path and is
    ///   never wired into the pull path, so a stray section is rejected rather
    ///   than ignored.
    /// - At most one pull backend (registry / s3 / oss / http-proxy) may drive
    ///   the daemon; more than one is ambiguous.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.localfs.is_some() {
            return Err(ConfigError::LocalFsNotAPullBackend);
        }
        let pulls = self.pull_backends();
        if pulls.len() > 1 {
            return Err(ConfigError::MultiplePullBackends {
                configured: pulls.join(", "),
            });
        }
        Ok(())
    }
}

impl SnapshotterConfig {
    /// Validate the parsed configuration after [`Self::resolve_profile`].
    /// Currently checks the `[backends.*]` selection; extend as new
    /// cross-section invariants appear.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.backends.validate()
    }
}

/// Registry backend configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegistryBackendConfig {
    /// Mirror endpoints.
    #[serde(default)]
    pub mirrors: Vec<String>,
    /// Skip TLS verification. Disables validation of the registry's serving
    /// certificate. SECURITY: only for trusted networks / test registries — a
    /// MITM can impersonate the registry when this is on.
    #[serde(default)]
    pub skip_verify: bool,
    /// Paths to PEM-encoded CA certificate bundle files to trust in addition to
    /// the system CA store. Use this (rather than `skip_verify`) for a registry
    /// served with a self-signed / private-CA certificate.
    #[serde(default)]
    pub ca_cert_files: Vec<String>,
    /// Use plain HTTP (no TLS) when the daemon pulls blobs from the registry.
    /// Needed for insecure/local registries (e.g. CI test registries); the daemon
    /// otherwise defaults to HTTPS.
    #[serde(default)]
    pub plain_http: bool,
    /// Request timeout (e.g. "30s").
    #[serde(default = "default_request_timeout")]
    pub request_timeout: String,
}

/// S3 backend configuration.
///
/// `endpoint` should be a BARE HOST (e.g. `s3.us-east-1.amazonaws.com` or
/// `minio.local:9000`): the storage backend builds the object URL as
/// `{scheme}://{endpoint}/...`, so the scheme is selected separately via
/// `insecure`. As a convenience a scheme-prefixed endpoint (`http://` /
/// `https://`) is accepted and the explicit prefix wins over `insecure` — see
/// [`crate::daemon::config_builder`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct S3BackendConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_env: String,
    pub secret_key_env: String,
    /// Use plain HTTP instead of HTTPS for a bare-host `endpoint` (e.g. an
    /// on-prem MinIO served over http). Ignored when `endpoint` already
    /// carries an explicit scheme. Default `false` (HTTPS).
    #[serde(default)]
    pub insecure: bool,
    /// Optional object-key prefix simulating a subdirectory layout, e.g.
    /// `nydus/` → object key `nydus/sha256:xxx`. `None` means no prefix.
    #[serde(default)]
    pub object_prefix: Option<String>,
    /// Skip TLS verification for an HTTPS endpoint. SECURITY: only for trusted
    /// networks — a MITM can impersonate the endpoint when this is on. Prefer
    /// `ca_cert_files` for a self-signed / private-CA endpoint.
    #[serde(default)]
    pub skip_verify: bool,
    /// Paths to PEM-encoded CA certificate bundle files to trust in addition to
    /// the system CA store, for an endpoint served with a self-signed / private
    /// CA certificate.
    #[serde(default)]
    pub ca_cert_files: Vec<String>,
}

/// OSS backend configuration.
///
/// `endpoint` follows the same BARE-HOST convention as [`S3BackendConfig`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OssBackendConfig {
    pub endpoint: String,
    pub bucket: String,
    /// Name of the environment variable holding the OSS access-key id.
    /// Empty (the default) means anonymous / public-bucket access — the
    /// resolved credential is left blank. Mirrors [`S3BackendConfig`].
    #[serde(default)]
    pub access_key_env: String,
    /// Name of the environment variable holding the OSS access-key secret.
    #[serde(default)]
    pub secret_key_env: String,
    /// Use plain HTTP instead of HTTPS for a bare-host `endpoint`. Ignored when
    /// `endpoint` already carries an explicit scheme. Default `false` (HTTPS).
    #[serde(default)]
    pub insecure: bool,
    /// Optional object-key prefix simulating a subdirectory layout, e.g.
    /// `nydus/`. `None` means no prefix.
    #[serde(default)]
    pub object_prefix: Option<String>,
    /// Skip TLS verification for an HTTPS endpoint. SECURITY: only for trusted
    /// networks — a MITM can impersonate the endpoint when this is on. Prefer
    /// `ca_cert_files` for a self-signed / private-CA endpoint.
    #[serde(default)]
    pub skip_verify: bool,
    /// Paths to PEM-encoded CA certificate bundle files to trust in addition to
    /// the system CA store, for an endpoint served with a self-signed / private
    /// CA certificate.
    #[serde(default)]
    pub ca_cert_files: Vec<String>,
}

/// Local filesystem backend configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LocalFsBackendConfig {
    pub dir: PathBuf,
}

/// HTTP proxy backend configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpProxyBackendConfig {
    /// Address of the http proxy server, like `http://host:port`,
    /// `https://host:port`, or a `/path/to/unix.sock`. Maps to the api
    /// `HttpProxyConfig::addr`.
    pub url: String,
    /// Blob path prefix appended to the proxy URL, like `/<namespace>/<repo>/blobs`.
    /// `None` (the default) maps to an empty path — correct for a unix-socket
    /// proxy, which ignores the path entirely. Set it for an http proxy that
    /// serves blobs under a non-root prefix.
    #[serde(default)]
    pub path: Option<String>,
    /// Skip TLS verification for an HTTPS proxy URL. SECURITY: only for trusted
    /// networks — a MITM can impersonate the proxy when this is on. Prefer
    /// `ca_cert_files` for a self-signed / private-CA proxy.
    #[serde(default)]
    pub skip_verify: bool,
    /// Paths to PEM-encoded CA certificate bundle files to trust in addition to
    /// the system CA store, for an HTTPS proxy served with a self-signed /
    /// private CA certificate.
    #[serde(default)]
    pub ca_cert_files: Vec<String>,
}

// ── Default value helpers ──────────────────────────────────────────────

fn default_root() -> PathBuf {
    PathBuf::from("/var/lib/containerd-nydus")
}
fn default_address() -> PathBuf {
    PathBuf::from("/run/containerd-nydus/containerd-nydus-grpc.sock")
}
fn default_sysctl_address() -> PathBuf {
    PathBuf::from("/run/containerd-nydus/containerd-nydus-api.sock")
}
fn default_recover_policy() -> String {
    "failover".to_string()
}
fn default_fdstore_warn_threshold() -> usize {
    96
}
fn default_recon_period() -> String {
    "5m".to_string()
}
fn default_mount_probe_timeout() -> String {
    "2s".to_string()
}
fn default_threads() -> usize {
    4
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_cache_work_dir() -> PathBuf {
    PathBuf::from("/var/lib/containerd-nydus/cache")
}
fn default_gc_period() -> String {
    "24h".to_string()
}
fn default_request_timeout() -> String {
    "30s".to_string()
}
fn default_true() -> bool {
    true
}
fn default_auto_zran_nydus_image() -> PathBuf {
    PathBuf::from("/usr/local/bin/nydus-image")
}
fn default_auto_zran_queue_depth() -> usize {
    128
}
fn default_auto_zran_nice() -> i32 {
    19
}
fn default_auto_zran_work_dir() -> PathBuf {
    PathBuf::from("/var/lib/containerd-nydus/auto-zran")
}
fn default_capture_settle_idle() -> String {
    "5s".to_string()
}
fn default_capture_settle_max() -> String {
    "60s".to_string()
}
fn default_capture_min_files() -> usize {
    1
}
fn default_capture_max_files() -> usize {
    4096
}
fn default_capture_exclude_globs() -> Vec<String> {
    vec![
        "/proc/**".to_string(),
        "/sys/**".to_string(),
        "/dev/**".to_string(),
        "/tmp/**".to_string(),
        "/run/**".to_string(),
        "/var/run/**".to_string(),
    ]
}
fn default_containerd_namespace() -> String {
    "k8s.io".to_string()
}
fn default_query_template() -> String {
    // Spegel's load-bearing `?ns=<registry>` quirk, expressed as a template.
    "ns={registry}".to_string()
}
fn default_peer_mirror_discovery_ttl() -> String {
    "5m".to_string()
}
fn default_peer_mirror_request_timeout() -> String {
    "10s".to_string()
}

fn default_fs_drivers() -> Vec<FsDriverEntry> {
    vec![
        FsDriverEntry {
            driver_type: FsDriverType::Fanotify,
            min_kernel: Some("6.14".to_string()),
            require_caps: vec!["CAP_SYS_ADMIN".to_string()],
            mode: None,
        },
        FsDriverEntry {
            driver_type: FsDriverType::Blockdev,
            min_kernel: None,
            require_caps: vec!["CAP_SYS_ADMIN".to_string()],
            mode: Some("loop".to_string()),
        },
        FsDriverEntry {
            driver_type: FsDriverType::Fusedev,
            min_kernel: None,
            require_caps: vec![],
            mode: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example config shipped in the release tarball must always parse
    /// and validate against the current schema.
    #[test]
    fn shipped_example_config_parses_and_validates() {
        let example = include_str!("../../../misc/configs/containerd-nydus-config.toml");
        let config: SnapshotterConfig = toml::from_str(example).expect("example config parses");
        config.validate().expect("example config validates");
        assert_eq!(config.snapshotter.profile, Profile::Containerd);
        assert!(config.snapshotter.sysctl.enable);
        assert!(!config.snapshotter.auto_zran.enable);
    }

    #[test]
    fn fs_driver_type_hint_roundtrip_and_tarfs() {
        for d in [
            FsDriverType::Fanotify,
            FsDriverType::Fusedev,
            FsDriverType::Blockdev,
            FsDriverType::Tarfs,
        ] {
            assert_eq!(FsDriverType::from_hint(d.as_str()), Some(d));
        }
        // Case-insensitive + trimmed, matching the label value in the wild.
        assert_eq!(
            FsDriverType::from_hint("  TARFS "),
            Some(FsDriverType::Tarfs)
        );
        assert_eq!(FsDriverType::from_hint("nope"), None);
        assert_eq!(FsDriverType::Tarfs.as_str(), "tarfs");
    }

    #[test]
    fn tarfs_config_defaults_verity_on() {
        let cfg = TarfsConfig::default();
        assert!(cfg.verity, "dm-verity must default on for tarfs");
        assert_eq!(cfg.veritysetup_path, PathBuf::from("veritysetup"));
        assert_eq!(cfg.losetup_path, PathBuf::from("losetup"));
        // An omitted `[snapshotter.tarfs]` table deserializes to the same.
        let de: TarfsConfig = toml::from_str("").unwrap();
        assert!(de.verity);
    }

    #[test]
    fn tarfs_driver_deserializes_from_config() {
        let toml = r#"
            [[snapshotter.fs_drivers]]
            type = "tarfs"
            require_caps = ["CAP_SYS_ADMIN"]

            [snapshotter.tarfs]
            verity = false
        "#;
        let cfg: SnapshotterConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.snapshotter.fs_drivers[0].driver_type,
            FsDriverType::Tarfs
        );
        assert!(!cfg.snapshotter.tarfs.verity);
    }

    /// Referrer detection now ships ON (serving is implemented + e2e-verified;
    /// every failure falls through to overlay). Pin both the struct default and
    /// the "field absent from TOML" deserialize default so a config that never
    /// mentions the flag gets detection enabled, and the two paths agree.
    #[test]
    fn referrer_detect_defaults_on() {
        assert!(
            SnapshotterConfig::default()
                .snapshotter
                .features
                .referrer_detect,
            "referrer_detect must default on"
        );
        let features: FeaturesConfig =
            toml::from_str("").expect("empty features table must deserialize");
        assert!(
            features.referrer_detect,
            "an omitted referrer_detect must deserialize to on"
        );
        // An explicit opt-out must still be honoured.
        let disabled: FeaturesConfig =
            toml::from_str("referrer_detect = false").expect("explicit opt-out must deserialize");
        assert!(
            !disabled.referrer_detect,
            "an explicit referrer_detect = false must stay off"
        );
    }

    /// Pins the manual `Default for FeaturesConfig` to the serde field
    /// defaults for EVERY field, so the derive-vs-serde drift that once made
    /// `SnapshotterConfig::default()` disagree with an empty `[features]`
    /// table (prefetch/metrics silently false) cannot recur when a field is
    /// added or its default changes.
    #[test]
    fn features_default_matches_empty_toml_for_all_fields() {
        let structural = FeaturesConfig::default();
        let deserialized: FeaturesConfig =
            toml::from_str("").expect("empty features table must deserialize");
        assert_eq!(
            structural.referrer_detect, deserialized.referrer_detect,
            "referrer_detect: Default and serde default diverge"
        );
        assert_eq!(
            structural.encryption, deserialized.encryption,
            "encryption: Default and serde default diverge"
        );
        assert_eq!(
            structural.prefetch, deserialized.prefetch,
            "prefetch: Default and serde default diverge"
        );
        assert_eq!(
            structural.metrics, deserialized.metrics,
            "metrics: Default and serde default diverge"
        );
        assert_eq!(
            structural.erofs_page_cache_sharing, deserialized.erofs_page_cache_sharing,
            "erofs_page_cache_sharing: Default and serde default diverge"
        );
    }

    #[test]
    fn parse_minimal_config() {
        let toml_str = r#"
[snapshotter]
root = "/tmp/nydus-test"
address = "/tmp/nydus-test.sock"

[snapshotter.daemon]
recover_policy = "restart"

[[snapshotter.fs_drivers]]
type = "fusedev"

[snapshotter.cache]
work_dir = "/tmp/nydus-test/cache"
gc_period = "12h"
gc_max_age = "168h"
gc_max_bytes = 1048576
gc_dry_run = true

[snapshotter.sysctl]
enable = true
address = "/tmp/nydus-test-api.sock"

[backends.registry]
skip_verify = true
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse config");
        assert_eq!(config.snapshotter.root, PathBuf::from("/tmp/nydus-test"));
        assert_eq!(
            config.snapshotter.fs_driver_policy,
            FsDriverSelectionPolicy::Auto
        );
        assert_eq!(config.snapshotter.fs_drivers.len(), 1);
        assert_eq!(
            config.snapshotter.fs_drivers[0].driver_type,
            FsDriverType::Fusedev
        );
        assert_eq!(config.snapshotter.cache.gc_period, "12h");
        assert_eq!(config.snapshotter.cache.gc_max_age.as_deref(), Some("168h"));
        assert_eq!(config.snapshotter.cache.gc_max_bytes, Some(1048576));
        assert!(config.snapshotter.cache.gc_dry_run);
        assert!(config.snapshotter.sysctl.enable);
        assert_eq!(
            config.snapshotter.sysctl.address,
            PathBuf::from("/tmp/nydus-test-api.sock")
        );
        let registry = config.backends.registry.as_ref().unwrap();
        assert!(registry.skip_verify);
    }

    #[test]
    fn default_config_enables_sysctl_api() {
        let config = SnapshotterConfig::default();
        assert_eq!(
            config.snapshotter.fs_driver_policy,
            FsDriverSelectionPolicy::Auto
        );
        assert_eq!(config.snapshotter.fs_drivers.len(), 3);
        assert_eq!(
            config.snapshotter.fs_drivers[0].driver_type,
            FsDriverType::Fanotify
        );
        assert_eq!(
            config.snapshotter.fs_drivers[1].driver_type,
            FsDriverType::Blockdev
        );
        assert_eq!(
            config.snapshotter.fs_drivers[1].mode.as_deref(),
            Some("loop")
        );
        assert_eq!(
            config.snapshotter.fs_drivers[2].driver_type,
            FsDriverType::Fusedev
        );
        assert!(config.snapshotter.sysctl.enable);
        assert_eq!(
            config.snapshotter.sysctl.address,
            PathBuf::from("/run/containerd-nydus/containerd-nydus-api.sock")
        );
        assert!(!config.snapshotter.auto_zran.enable);
        assert_eq!(config.snapshotter.auto_zran.sched_class, SchedClass::Idle);
        assert_eq!(config.snapshotter.auto_zran.nice, 19);
        assert!(config.snapshotter.auto_zran.capture.enable);
        assert_eq!(config.snapshotter.containerd.namespace, "k8s.io");
        // The TCP metrics endpoint is opt-in: with no `[snapshotter.metrics]`
        // section the listener is unset, so behavior is UDS-only as before.
        assert_eq!(config.snapshotter.metrics.listen, None);
    }

    #[test]
    fn default_config_has_no_tcp_metrics_listener() {
        // Parsing a config that omits `[snapshotter.metrics]` must leave the TCP
        // metrics listener unset (no additive TCP endpoint), preserving today's
        // UDS-only behavior.
        let config: SnapshotterConfig =
            toml::from_str("[snapshotter]\n").expect("parse config without metrics section");
        assert_eq!(config.snapshotter.metrics.listen, None);
    }

    #[test]
    fn parse_metrics_listen_config() {
        let toml_str = r#"
[snapshotter.metrics]
listen = "127.0.0.1:9110"
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse config");
        assert_eq!(
            config.snapshotter.metrics.listen.as_deref(),
            Some("127.0.0.1:9110")
        );
    }

    #[test]
    fn parse_auto_zran_config() {
        let toml_str = r#"
[snapshotter.auto_zran]
enable = true
nydus_image = "/opt/nydus-image"
queue_depth = 8
nice = 15
sched_class = "normal"
work_dir = "/var/tmp/nydus-zran"

[snapshotter.auto_zran.capture]
settle_idle = "10s"
settle_max = "120s"
min_files = 5
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse config");
        assert!(config.snapshotter.auto_zran.enable);
        assert_eq!(
            config.snapshotter.auto_zran.nydus_image,
            PathBuf::from("/opt/nydus-image")
        );
        assert_eq!(config.snapshotter.auto_zran.queue_depth, 8);
        assert_eq!(config.snapshotter.auto_zran.nice, 15);
        assert_eq!(config.snapshotter.auto_zran.sched_class, SchedClass::Normal);
        assert_eq!(
            config.snapshotter.auto_zran.work_dir,
            PathBuf::from("/var/tmp/nydus-zran")
        );
        assert_eq!(config.snapshotter.auto_zran.capture.settle_idle, "10s");
        assert_eq!(config.snapshotter.auto_zran.capture.settle_max, "120s");
        assert_eq!(config.snapshotter.auto_zran.capture.min_files, 5);
    }

    #[test]
    fn parse_ordered_driver_policy_override() {
        let toml_str = r#"
[snapshotter]
fs_driver_policy = "ordered"

[[snapshotter.fs_drivers]]
type = "fusedev"

[[snapshotter.fs_drivers]]
type = "fanotify"
min_kernel = "6.14"
require_caps = ["CAP_SYS_ADMIN"]
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse config");
        assert_eq!(
            config.snapshotter.fs_driver_policy,
            FsDriverSelectionPolicy::Ordered
        );
        assert_eq!(
            config.snapshotter.fs_drivers[0].driver_type,
            FsDriverType::Fusedev
        );
        assert_eq!(
            config.snapshotter.fs_drivers[1].driver_type,
            FsDriverType::Fanotify
        );
    }

    #[test]
    fn reject_fscache_driver() {
        let toml_str = r#"
[snapshotter]
root = "/tmp/nydus-test"
address = "/tmp/nydus-test.sock"

[[snapshotter.fs_drivers]]
type = "fscache"
"#;
        let result = toml::from_str::<SnapshotterConfig>(toml_str);
        assert!(result.is_err(), "fscache driver type must be rejected");
    }

    // ── B1: profile resolution ─────────────────────────────────────────

    /// Probe that reports the given set of present socket paths.
    fn probe_present(present: &'static [&'static str]) -> impl Fn(&std::path::Path) -> bool {
        move |p: &std::path::Path| present.iter().any(|s| std::path::Path::new(s) == p)
    }

    #[test]
    fn resolve_profile_explicit_values_win() {
        // Operator set both host paths AND profile = containerd; the k3s
        // probe would say k3s, but explicit values must be untouched.
        let toml_str = r#"
[snapshotter]
profile = "containerd"

[snapshotter.containerd]
address = "/custom/containerd.sock"
content_root = "/custom/content"
"#;
        let mut config: SnapshotterConfig = toml::from_str(toml_str).expect("parse");
        let rp = config
            .resolve_profile_with(probe_present(&[
                K3S_CONTAINERD_SOCKET,
                STOCK_CONTAINERD_SOCKET,
            ]))
            .expect("resolve");
        assert_eq!(rp.profile, Profile::Containerd);
        assert_eq!(
            config.snapshotter.containerd.address(),
            PathBuf::from("/custom/containerd.sock")
        );
        assert_eq!(
            config.snapshotter.containerd.content_root(),
            PathBuf::from("/custom/content")
        );
    }

    #[test]
    fn resolve_profile_auto_detects_k3s() {
        let mut config = SnapshotterConfig::default();
        let rp = config
            .resolve_profile_with(probe_present(&[K3S_CONTAINERD_SOCKET]))
            .expect("resolve");
        assert_eq!(rp.profile, Profile::K3s);
        assert_eq!(
            config.snapshotter.containerd.address(),
            PathBuf::from(K3S_CONTAINERD_SOCKET)
        );
        assert_eq!(
            config.snapshotter.containerd.content_root(),
            PathBuf::from("/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content")
        );
        assert_eq!(
            config.snapshotter.peer_mirror.preset,
            Some(MirrorPreset::K3sSpegel)
        );
    }

    #[test]
    fn resolve_profile_auto_detects_containerd() {
        let mut config = SnapshotterConfig::default();
        let rp = config
            .resolve_profile_with(probe_present(&[STOCK_CONTAINERD_SOCKET]))
            .expect("resolve");
        assert_eq!(rp.profile, Profile::Containerd);
        assert_eq!(
            config.snapshotter.containerd.address(),
            PathBuf::from(STOCK_CONTAINERD_SOCKET)
        );
        assert_eq!(
            config.snapshotter.containerd.content_root(),
            PathBuf::from("/var/lib/containerd/io.containerd.content.v1.content")
        );
        assert_eq!(
            config.snapshotter.peer_mirror.preset,
            Some(MirrorPreset::None)
        );
    }

    #[test]
    fn resolve_profile_auto_both_sockets_is_ambiguous_error() {
        let mut config = SnapshotterConfig::default();
        let err = config
            .resolve_profile_with(probe_present(&[
                K3S_CONTAINERD_SOCKET,
                STOCK_CONTAINERD_SOCKET,
            ]))
            .expect_err("both sockets must be ambiguous");
        assert!(matches!(err, ConfigError::AmbiguousProfile));
    }

    #[test]
    fn resolve_profile_auto_neither_socket_errors_when_auto_zran_enabled() {
        let mut config = SnapshotterConfig::default();
        config.snapshotter.auto_zran.enable = true;
        let err = config
            .resolve_profile_with(probe_present(&[]))
            .expect_err("no socket + auto_zran must error");
        assert!(matches!(err, ConfigError::NoContainerdSocket));
    }

    #[test]
    fn resolve_profile_auto_detects_k3s_by_install_dir_before_socket_exists() {
        // Clean-boot ordering: the snapshotter starts before k3s, so the k3s
        // socket doesn't exist yet — but the boot-stable install dir does. The
        // node must still resolve to the k3s profile (not silently to
        // containerd), even with auto_zran enabled.
        let mut config = SnapshotterConfig::default();
        config.snapshotter.auto_zran.enable = true;
        let rp = config
            .resolve_profile_with(probe_present(&[K3S_DATA_DIR]))
            .expect("k3s install dir must resolve to k3s profile");
        assert_eq!(rp.profile, Profile::K3s);
    }

    #[test]
    fn resolve_profile_auto_k3s_etc_dir_also_detects_k3s() {
        let mut config = SnapshotterConfig::default();
        let rp = config
            .resolve_profile_with(probe_present(&[K3S_ETC_DIR]))
            .expect("k3s etc dir must resolve to k3s profile");
        assert_eq!(rp.profile, Profile::K3s);
    }

    #[test]
    fn resolve_profile_auto_neither_socket_defaults_containerd_when_auto_zran_disabled() {
        let mut config = SnapshotterConfig::default();
        assert!(!config.snapshotter.auto_zran.enable);
        let rp = config
            .resolve_profile_with(probe_present(&[]))
            .expect("resolve");
        assert_eq!(rp.profile, Profile::Containerd);
    }

    /// The accessor `.unwrap_or` fallback arms are only hit when
    /// `resolve_profile` was NOT run (all Option fields still `None`). Every
    /// other test resolves first, so pin the unresolved fallbacks here to the
    /// stock-containerd defaults — a drift in the fallback consts would flip
    /// out-of-box behaviour on a config that never resolved.
    #[test]
    fn unresolved_accessors_return_stock_defaults() {
        let config = SnapshotterConfig::default();
        let c = &config.snapshotter.containerd;
        assert_eq!(c.address(), PathBuf::from(STOCK_CONTAINERD_SOCKET));
        assert_eq!(c.content_root(), PathBuf::from(STOCK_CONTENT_ROOT));

        let pm = &config.snapshotter.peer_mirror;
        assert!(!pm.is_enabled());
        assert_eq!(pm.endpoint(), DEFAULT_MIRROR_ENDPOINT);
        assert_eq!(pm.peer_discovery(), PeerDiscoveryMode::Off);
        assert_eq!(pm.ca_path(), None);
        assert_eq!(pm.client_cert_path(), None);
        assert_eq!(pm.client_key_path(), None);
    }

    // ── B2: back-compat + preset + query template ──────────────────────

    /// #1 ACCEPTANCE: an existing k3s config using the legacy
    /// `[snapshotter.spegel_mirror]` table with only `enable = true`, on a
    /// k3s host (auto → k3s), must reproduce today's Spegel behaviour byte
    /// for byte: enable, endpoint, discovery, and mTLS cert paths.
    #[test]
    fn legacy_spegel_mirror_alias_reproduces_k3s_behaviour() {
        let toml_str = r#"
[snapshotter.containerd]
address = "/run/k3s/containerd/containerd.sock"
content_root = "/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content"

[snapshotter.spegel_mirror]
enable = true
"#;
        let mut config: SnapshotterConfig = toml::from_str(toml_str).expect("parse legacy config");
        // Alias parsed into peer_mirror with enable explicitly set.
        assert_eq!(config.snapshotter.peer_mirror.enable, Some(true));
        // Resolve on a k3s host.
        config
            .resolve_profile_with(probe_present(&[K3S_CONTAINERD_SOCKET]))
            .expect("resolve");
        let pm = &config.snapshotter.peer_mirror;
        assert_eq!(pm.preset, Some(MirrorPreset::K3sSpegel));
        assert!(pm.is_enabled());
        assert_eq!(pm.endpoint(), "https://127.0.0.1:6443");
        // Discovery now defaults OFF (native Spegel routing); the enable /
        // endpoint / mTLS cert paths are still reproduced byte-for-byte.
        assert_eq!(pm.peer_discovery(), PeerDiscoveryMode::Off);
        assert_eq!(
            pm.ca_path(),
            Some(std::path::Path::new(
                "/var/lib/rancher/k3s/agent/server-ca.crt"
            ))
        );
        assert_eq!(
            pm.client_cert_path(),
            Some(std::path::Path::new(
                "/var/lib/rancher/k3s/agent/client-k3s-controller.crt"
            ))
        );
        assert_eq!(
            pm.client_key_path(),
            Some(std::path::Path::new(
                "/var/lib/rancher/k3s/agent/client-k3s-controller.key"
            ))
        );
        // The Spegel `?ns=` query is still emitted.
        assert_eq!(
            pm.artifact_query("example.com"),
            Some("ns=example.com".to_string())
        );
    }

    #[test]
    fn preset_derives_discovery_default() {
        // Every preset now defaults discovery ⇒ off (native Spegel routing);
        // `kubernetes` is opt-in only.
        for (preset, expected) in [
            (MirrorPreset::K3sSpegel, PeerDiscoveryMode::Off),
            (MirrorPreset::Spegel, PeerDiscoveryMode::Off),
            (MirrorPreset::None, PeerDiscoveryMode::Off),
        ] {
            let mut config = SnapshotterConfig::default();
            config.snapshotter.peer_mirror.preset = Some(preset);
            config
                .resolve_profile_with(probe_present(&[STOCK_CONTAINERD_SOCKET]))
                .expect("resolve");
            assert_eq!(
                config.snapshotter.peer_mirror.peer_discovery(),
                expected,
                "preset {preset:?} discovery default"
            );
        }
    }

    #[test]
    fn explicit_peer_discovery_overrides_preset_default() {
        let toml_str = r#"
[snapshotter]
profile = "k3s"

[snapshotter.peer_mirror]
peer_discovery = "kubernetes"
"#;
        let mut config: SnapshotterConfig = toml::from_str(toml_str).expect("parse");
        config
            .resolve_profile_with(probe_present(&[K3S_CONTAINERD_SOCKET]))
            .expect("resolve");
        // k3s-spegel now defaults off, but the operator opted into the
        // kubernetes node fan-out fallback explicitly.
        assert_eq!(
            config.snapshotter.peer_mirror.peer_discovery(),
            PeerDiscoveryMode::Kubernetes
        );
    }

    #[test]
    fn query_template_expansion_and_empty() {
        assert_eq!(
            expand_query_template("ns={registry}", "docker.io"),
            Some("ns=docker.io".to_string())
        );
        assert_eq!(expand_query_template("", "docker.io"), None);
        // A template without the placeholder is emitted verbatim.
        assert_eq!(
            expand_query_template("static=1", "docker.io"),
            Some("static=1".to_string())
        );
    }

    #[test]
    fn empty_query_template_yields_no_query() {
        let toml_str = r#"
[snapshotter.peer_mirror]
query_template = ""
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(
            config.snapshotter.peer_mirror.artifact_query("docker.io"),
            None
        );
    }

    // ── B3: backend selection validation ───────────────────────────────

    #[test]
    fn validate_rejects_orphan_localfs_backend() {
        let toml_str = r#"
[snapshotter]

[backends.localfs]
dir = "/var/lib/blobs"
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse");
        let err = config.validate().expect_err("localfs must be rejected");
        assert!(matches!(err, ConfigError::LocalFsNotAPullBackend));
    }

    #[test]
    fn validate_rejects_multiple_pull_backends() {
        let toml_str = r#"
[snapshotter]

[backends.registry]
skip_verify = true

[backends.s3]
endpoint = "https://s3.example.com"
region = "us-east-1"
bucket = "b"
access_key_env = "AK"
secret_key_env = "SK"
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse");
        let err = config
            .validate()
            .expect_err("registry + s3 must be ambiguous");
        match err {
            ConfigError::MultiplePullBackends { configured } => {
                assert!(configured.contains("registry"));
                assert!(configured.contains("s3"));
            }
            other => panic!("expected MultiplePullBackends, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_single_s3_backend() {
        let toml_str = r#"
[snapshotter]

[backends.s3]
endpoint = "https://s3.example.com"
region = "us-east-1"
bucket = "b"
access_key_env = "AK"
secret_key_env = "SK"
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse");
        config.validate().expect("single s3 backend is valid");
        assert_eq!(config.backends.pull_backends(), vec!["s3"]);
    }

    #[test]
    fn validate_accepts_empty_and_registry_only_backends() {
        // Default (no backends) and registry-only both validate.
        SnapshotterConfig::default()
            .validate()
            .expect("empty backends valid");
        let toml_str = r#"
[snapshotter]

[backends.registry]
skip_verify = true
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse");
        config.validate().expect("registry-only valid");
    }

    // ── Backend TLS / path knobs (additive, back-compat) ───────────────

    #[test]
    fn backend_tls_fields_default_when_omitted() {
        // Back-compat: existing configs that never mention the new TLS/path
        // fields must still parse, with the fields at their inert defaults
        // (skip_verify=false, ca_cert_files empty, http-proxy path None).
        let toml_str = r#"
[snapshotter]

[backends.registry]
skip_verify = true

[backends.s3]
endpoint = "s3.example.com"
region = "us-east-1"
bucket = "b"
access_key_env = "AK"
secret_key_env = "SK"

[backends.oss]
endpoint = "oss.example.com"
bucket = "b"

[backends.http_proxy]
url = "http://127.0.0.1:8000"
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse config");
        let reg = config.backends.registry.as_ref().unwrap();
        assert!(reg.ca_cert_files.is_empty());
        let s3 = config.backends.s3.as_ref().unwrap();
        assert!(!s3.skip_verify);
        assert!(s3.ca_cert_files.is_empty());
        let oss = config.backends.oss.as_ref().unwrap();
        assert!(!oss.skip_verify);
        assert!(oss.ca_cert_files.is_empty());
        let hp = config.backends.http_proxy.as_ref().unwrap();
        assert_eq!(hp.path, None);
        assert!(!hp.skip_verify);
        assert!(hp.ca_cert_files.is_empty());
    }

    #[test]
    fn backend_tls_fields_parse_when_present() {
        let toml_str = r#"
[snapshotter]

[backends.http_proxy]
url = "https://proxy.example.com"
path = "/blobs"
skip_verify = true
ca_cert_files = ["/etc/proxy-ca.pem"]
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse config");
        let hp = config.backends.http_proxy.as_ref().unwrap();
        assert_eq!(hp.url, "https://proxy.example.com");
        assert_eq!(hp.path.as_deref(), Some("/blobs"));
        assert!(hp.skip_verify);
        assert_eq!(hp.ca_cert_files, vec!["/etc/proxy-ca.pem".to_string()]);
    }

    #[test]
    fn registry_ca_cert_files_parse() {
        let toml_str = r#"
[snapshotter]

[backends.registry]
ca_cert_files = ["/etc/ca.pem"]
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse config");
        let reg = config.backends.registry.as_ref().unwrap();
        assert_eq!(reg.ca_cert_files, vec!["/etc/ca.pem".to_string()]);
    }

    #[test]
    fn peer_mirror_new_name_also_parses() {
        // The new canonical name works alongside the legacy alias.
        let toml_str = r#"
[snapshotter.peer_mirror]
preset = "spegel"
enable = true
endpoint = "http://127.0.0.1:5000"
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(
            config.snapshotter.peer_mirror.preset,
            Some(MirrorPreset::Spegel)
        );
        assert_eq!(config.snapshotter.peer_mirror.enable, Some(true));
        assert_eq!(
            config.snapshotter.peer_mirror.endpoint(),
            "http://127.0.0.1:5000"
        );
    }
}
