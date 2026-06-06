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
}

impl Default for SnapshotterSection {
    fn default() -> Self {
        Self {
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
        }
    }
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
    /// Path to containerd's gRPC socket.
    #[serde(default = "default_containerd_address")]
    pub address: PathBuf,
    /// Containerd namespace to operate in. For k3s/CRI this is `k8s.io`.
    #[serde(default = "default_containerd_namespace")]
    pub namespace: String,
    /// Root of containerd's content store on disk. Used for `blob_path`
    /// resolution (so we can pass already-committed blobs into the fanotify
    /// backend dir as symlinks). The well-known layout is stable across
    /// containerd 1.x and 2.x: `<root>/blobs/sha256/<hex>`.
    #[serde(default = "default_containerd_content_root")]
    pub content_root: PathBuf,
}

impl Default for ContainerdConfig {
    fn default() -> Self {
        Self {
            address: default_containerd_address(),
            namespace: default_containerd_namespace(),
            content_root: default_containerd_content_root(),
        }
    }
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
fn default_containerd_address() -> PathBuf {
    PathBuf::from("/run/k3s/containerd/containerd.sock")
}
fn default_containerd_namespace() -> String {
    "k8s.io".to_string()
}
fn default_containerd_content_root() -> PathBuf {
    PathBuf::from("/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content")
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
}
