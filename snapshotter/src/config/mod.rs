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
    pub sysctl: SysctlConfig,

    #[serde(default)]
    pub features: FeaturesConfig,

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
            sysctl: SysctlConfig::default(),
            features: FeaturesConfig::default(),
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
                        if auto_zran_enabled {
                            return Err(ConfigError::NoContainerdSocket);
                        }
                        ResolvedProfile {
                            profile: Profile::Containerd,
                            reason: "no containerd socket detected; defaulting to containerd \
                                     (auto_zran disabled)"
                                .to_string(),
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
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FsDriverType {
    Fanotify,
    Fusedev,
    Blockdev,
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

/// Feature flags.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FeaturesConfig {
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
    /// Preset-derived when unset: the `k3s-spegel` preset defaults to
    /// `kubernetes` (a documented workaround for Spegel DHT rot — see
    /// [`crate::peer_mirror`]); every other preset defaults to `off`
    /// (local-mirror-only).
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
    /// order in tests. Example: `["https://node-b:6443"]`.
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
    /// cert paths, `kubernetes` peer discovery. Reproduces the historical
    /// `[snapshotter.spegel_mirror]` behaviour on k3s exactly.
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
                peer_discovery: PeerDiscoveryMode::Kubernetes,
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
    /// workaround; default only for the `k3s-spegel` preset.
    #[default]
    Kubernetes,
    /// Only the statically-configured `peer_endpoints`.
    Static,
    /// No peers — only the local mirror endpoint is tried.
    Off,
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

/// Registry backend configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegistryBackendConfig {
    /// Mirror endpoints.
    #[serde(default)]
    pub mirrors: Vec<String>,
    /// Skip TLS verification.
    #[serde(default)]
    pub skip_verify: bool,
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
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct S3BackendConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_env: String,
    pub secret_key_env: String,
}

/// OSS backend configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OssBackendConfig {
    pub endpoint: String,
    pub bucket: String,
}

/// Local filesystem backend configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LocalFsBackendConfig {
    pub dir: PathBuf,
}

/// HTTP proxy backend configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpProxyBackendConfig {
    pub url: String,
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
        assert_eq!(pm.peer_discovery(), PeerDiscoveryMode::Kubernetes);
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
        // k3s-spegel ⇒ kubernetes; spegel ⇒ off; none ⇒ off.
        for (preset, expected) in [
            (MirrorPreset::K3sSpegel, PeerDiscoveryMode::Kubernetes),
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
peer_discovery = "off"
"#;
        let mut config: SnapshotterConfig = toml::from_str(toml_str).expect("parse");
        config
            .resolve_profile_with(probe_present(&[K3S_CONTAINERD_SOCKET]))
            .expect("resolve");
        // k3s-spegel would default kubernetes, but the operator pinned off.
        assert_eq!(
            config.snapshotter.peer_mirror.peer_discovery(),
            PeerDiscoveryMode::Off
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
