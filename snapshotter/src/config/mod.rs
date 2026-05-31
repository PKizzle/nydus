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

    /// Background zran conversion for plain OCI images after runtime access
    /// profiles have been collected by the optimizer NRI plugin.
    #[serde(default)]
    pub auto_zran: AutoZranConfig,
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

/// Background zran conversion configuration.
///
/// The worker is intentionally disabled by default. When enabled, structured
/// prefetch profiles submitted by the optimizer NRI plugin enqueue a low-priority
/// `nydusify convert --oci-ref` job for the profiled image. Spegel or any other
/// registry mirror can then serve the generated OCI-reference artifact to other
/// nodes.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutoZranConfig {
    /// Enable automatic zran artifact generation.
    #[serde(default)]
    pub enable: bool,
    /// Path to the current nydusify binary. P7 will replace this CLI boundary
    /// with the Rust nydusify library.
    #[serde(default = "default_auto_zran_nydusify")]
    pub nydusify: PathBuf,
    /// Suffix appended to the source image reference when generating target
    /// artifact references.
    #[serde(default = "default_auto_zran_target_suffix")]
    pub target_suffix: String,
    /// Maximum queued conversion jobs before new profiles are dropped.
    #[serde(default = "default_auto_zran_queue_depth")]
    pub queue_depth: usize,
    /// Unix niceness for conversion subprocesses. Higher means lower CPU priority.
    #[serde(default = "default_auto_zran_nice")]
    pub nice: i32,
    /// Run conversion under `ionice -c 3` (idle I/O priority). Disable on
    /// systems where `ionice` is unavailable.
    #[serde(default = "default_true")]
    pub ionice_idle: bool,
    /// Working directory used by nydusify conversions.
    #[serde(default = "default_auto_zran_work_dir")]
    pub work_dir: PathBuf,
    /// Pass `--plain-http` to nydusify.
    #[serde(default)]
    pub plain_http: bool,
    /// Pass `--source-insecure` to nydusify.
    #[serde(default)]
    pub source_insecure: bool,
    /// Pass `--target-insecure` to nydusify.
    #[serde(default)]
    pub target_insecure: bool,
}

impl Default for AutoZranConfig {
    fn default() -> Self {
        Self {
            enable: false,
            nydusify: default_auto_zran_nydusify(),
            target_suffix: default_auto_zran_target_suffix(),
            queue_depth: default_auto_zran_queue_depth(),
            nice: default_auto_zran_nice(),
            ionice_idle: true,
            work_dir: default_auto_zran_work_dir(),
            plain_http: false,
            source_insecure: false,
            target_insecure: false,
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
fn default_auto_zran_nydusify() -> PathBuf {
    PathBuf::from("nydusify")
}
fn default_auto_zran_target_suffix() -> String {
    "-nydus-oci-ref".to_string()
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
        assert_eq!(config.snapshotter.auto_zran.target_suffix, "-nydus-oci-ref");
        assert_eq!(config.snapshotter.auto_zran.nice, 19);
    }

    #[test]
    fn parse_auto_zran_config() {
        let toml_str = r#"
[snapshotter.auto_zran]
enable = true
nydusify = "/usr/local/bin/nydusify"
target_suffix = "-zran"
queue_depth = 8
nice = 15
ionice_idle = false
work_dir = "/var/tmp/nydus-zran"
plain_http = true
source_insecure = true
target_insecure = true
"#;
        let config: SnapshotterConfig = toml::from_str(toml_str).expect("parse config");
        assert!(config.snapshotter.auto_zran.enable);
        assert_eq!(
            config.snapshotter.auto_zran.nydusify,
            PathBuf::from("/usr/local/bin/nydusify")
        );
        assert_eq!(config.snapshotter.auto_zran.target_suffix, "-zran");
        assert_eq!(config.snapshotter.auto_zran.queue_depth, 8);
        assert_eq!(config.snapshotter.auto_zran.nice, 15);
        assert!(!config.snapshotter.auto_zran.ionice_idle);
        assert_eq!(
            config.snapshotter.auto_zran.work_dir,
            PathBuf::from("/var/tmp/nydus-zran")
        );
        assert!(config.snapshotter.auto_zran.plain_http);
        assert!(config.snapshotter.auto_zran.source_insecure);
        assert!(config.snapshotter.auto_zran.target_insecure);
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
