// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Clone, Debug, Parser)]
#[command(
    name = "Nydusify",
    bin_name = "nydusify",
    about = "Nydus utility tool to convert, check, mount and copy container images",
    version
)]
pub struct Cli {
    #[arg(short = 'D', long = "debug", env = "DEBUG_LOG_LEVEL")]
    pub debug: bool,

    #[arg(short = 'l', long = "log-level", env = "LOG_LEVEL", default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    #[arg(long = "log-file", env = "LOG_FILE")]
    pub log_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Commands {
    /// Generate a Nydus image from an OCI image.
    Convert(Box<ConvertArgs>),
    /// Verify Nydus image format and content.
    Check(Box<CheckArgs>),
    /// Mount the Nydus image as a filesystem.
    Mount(Box<MountArgs>),
    /// Copy an image from source to target.
    Copy(Box<CopyArgs>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum BackendType {
    Registry,
    Oss,
    S3,
    Localfs,
}

impl BackendType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Oss => "oss",
            Self::S3 => "s3",
            Self::Localfs => "localfs",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct ConvertArgs {
    #[arg(long, env = "SOURCE")]
    pub source: String,
    #[arg(long = "source-archive", env = "SOURCE_ARCHIVE")]
    pub source_archive: Option<PathBuf>,
    #[arg(long, env = "TARGET")]
    pub target: Option<String>,
    #[arg(long = "target-archive", env = "TARGET_ARCHIVE")]
    pub target_archive: Option<PathBuf>,
    #[arg(
        long = "target-suffix",
        env = "TARGET_SUFFIX",
        allow_hyphen_values = true
    )]
    pub target_suffix: Option<String>,
    #[arg(long = "source-insecure", env = "SOURCE_INSECURE")]
    pub source_insecure: bool,
    #[arg(long = "target-insecure", env = "TARGET_INSECURE")]
    pub target_insecure: bool,
    /// Extra PEM CA certificate file(s) trusted in addition to the system
    /// store, for registries signed by a private CA (applies to both source
    /// and target). Repeatable; ignored when `--*-insecure` is set.
    #[arg(long = "ca-cert", env = "CA_CERT", value_delimiter = ',')]
    pub ca_cert: Vec<PathBuf>,
    #[arg(long = "source-backend-type", value_enum, env = "SOURCE_BACKEND_TYPE")]
    pub source_backend_type: Option<BackendType>,
    #[arg(long = "source-backend-config", env = "SOURCE_BACKEND_CONFIG")]
    pub source_backend_config: Option<String>,
    #[arg(
        long = "source-backend-config-file",
        env = "SOURCE_BACKEND_CONFIG_FILE"
    )]
    pub source_backend_config_file: Option<PathBuf>,
    #[arg(long = "backend-type", value_enum, env = "BACKEND_TYPE")]
    pub backend_type: Option<BackendType>,
    #[arg(long = "backend-config", env = "BACKEND_CONFIG")]
    pub backend_config: Option<String>,
    #[arg(long = "backend-config-file", env = "BACKEND_CONFIG_FILE")]
    pub backend_config_file: Option<PathBuf>,
    #[arg(long = "backend-force-push", env = "BACKEND_FORCE_PUSH")]
    pub backend_force_push: bool,
    #[arg(long = "build-cache", env = "BUILD_CACHE")]
    pub build_cache: Option<String>,
    #[arg(long = "build-cache-tag", env = "BUILD_CACHE_TAG")]
    pub build_cache_tag: Option<String>,
    #[arg(
        long = "build-cache-version",
        env = "BUILD_CACHE_VERSION",
        default_value = "v1"
    )]
    pub build_cache_version: String,
    #[arg(long = "build-cache-insecure", env = "BUILD_CACHE_INSECURE")]
    pub build_cache_insecure: bool,
    #[arg(
        long = "build-cache-max-records",
        env = "BUILD_CACHE_MAX_RECORDS",
        default_value_t = 200
    )]
    pub build_cache_max_records: u32,
    #[arg(long = "chunk-dict", env = "CHUNK_DICT")]
    pub chunk_dict: Option<String>,
    #[arg(long = "chunk-dict-insecure", env = "CHUNK_DICT_INSECURE")]
    pub chunk_dict_insecure: bool,
    #[arg(
        long = "merge-platform",
        alias = "multi-platform",
        env = "MERGE_PLATFORM"
    )]
    pub merge_platform: bool,
    #[arg(long = "all-platforms")]
    pub all_platforms: bool,
    /// Target platform (defaults to the host platform). Conflicts with --all-platforms.
    #[arg(long)]
    pub platform: Option<String>,
    #[arg(long = "oci-ref", env = "OCI_REF")]
    pub oci_ref: bool,
    #[arg(long = "with-referrer", env = "WITH_REFERRER")]
    pub with_referrer: bool,
    #[arg(long, env = "OCI")]
    pub oci: bool,
    #[arg(long, env = "REVERSE")]
    pub reverse: bool,
    #[arg(long = "fs-version", env = "FS_VERSION", default_value = "6")]
    pub fs_version: String,
    #[arg(long = "fs-align-chunk", env = "FS_ALIGN_CHUNK")]
    pub fs_align_chunk: bool,
    #[arg(long = "backend-aligned-chunk", env = "BACKEND_ALIGNED_CHUNK")]
    pub backend_aligned_chunk: bool,
    #[arg(long = "prefetch-dir", env = "PREFETCH_DIR")]
    pub prefetch_dir: Option<String>,
    #[arg(long = "prefetch-patterns", env = "PREFETCH_PATTERNS")]
    pub prefetch_patterns: bool,
    #[arg(long, env = "COMPRESSOR", default_value = "zstd")]
    pub compressor: String,
    #[arg(
        long = "fs-chunk-size",
        alias = "chunk-size",
        env = "FS_CHUNK_SIZE",
        default_value = "0x100000"
    )]
    pub fs_chunk_size: String,
    #[arg(long = "batch-size", env = "BATCH_SIZE", default_value = "0")]
    pub batch_size: String,
    #[arg(long = "work-dir", env = "WORK_DIR", default_value = "./tmp")]
    pub work_dir: PathBuf,
    #[arg(
        long = "nydus-image",
        env = "NYDUS_IMAGE",
        default_value = "nydus-image"
    )]
    pub nydus_image: PathBuf,
    #[arg(long = "output-json", env = "OUTPUT_JSON")]
    pub output_json: Option<PathBuf>,
    /// Speak plain HTTP to both registries. Shorthand for setting both
    /// `--source-plain-http` and `--target-plain-http`.
    #[arg(long = "plain-http", env = "PLAIN_HTTP")]
    pub plain_http: bool,
    /// Speak plain HTTP to the source registry only.
    #[arg(long = "source-plain-http", env = "SOURCE_PLAIN_HTTP")]
    pub source_plain_http: bool,
    /// Speak plain HTTP to the target registry only.
    ///
    /// Needed whenever the two ends disagree — e.g. converting an upstream
    /// image over HTTPS into a local test registry served over HTTP, which the
    /// single `--plain-http` switch cannot express.
    #[arg(long = "target-plain-http", env = "TARGET_PLAIN_HTTP")]
    pub target_plain_http: bool,
    #[arg(
        long = "push-retry-count",
        env = "PUSH_RETRY_COUNT",
        default_value_t = 3
    )]
    pub push_retry_count: u32,
    #[arg(
        long = "push-retry-delay",
        env = "PUSH_RETRY_DELAY",
        default_value = "5s"
    )]
    pub push_retry_delay: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct CheckArgs {
    #[arg(long, env = "SOURCE")]
    pub source: Option<String>,
    #[arg(long, env = "TARGET")]
    pub target: String,
    #[arg(long = "source-insecure", env = "SOURCE_INSECURE")]
    pub source_insecure: bool,
    #[arg(long = "target-insecure", env = "TARGET_INSECURE")]
    pub target_insecure: bool,
    /// Speak plain HTTP to both registries. Shorthand for both flags below.
    #[arg(long = "plain-http", env = "PLAIN_HTTP")]
    pub plain_http: bool,
    /// Speak plain HTTP to the source registry only.
    #[arg(long = "source-plain-http", env = "SOURCE_PLAIN_HTTP")]
    pub source_plain_http: bool,
    /// Speak plain HTTP to the target registry only.
    #[arg(long = "target-plain-http", env = "TARGET_PLAIN_HTTP")]
    pub target_plain_http: bool,
    /// Extra PEM CA certificate file(s) trusted in addition to the system
    /// store, for registries signed by a private CA (applies to both source
    /// and target). Repeatable; ignored when `--*-insecure` is set.
    #[arg(long = "ca-cert", env = "CA_CERT", value_delimiter = ',')]
    pub ca_cert: Vec<PathBuf>,
    #[arg(long = "source-backend-type", value_enum, env = "SOURCE_BACKEND_TYPE")]
    pub source_backend_type: Option<BackendType>,
    #[arg(long = "source-backend-config", env = "SOURCE_BACKEND_CONFIG")]
    pub source_backend_config: Option<String>,
    #[arg(
        long = "source-backend-config-file",
        env = "SOURCE_BACKEND_CONFIG_FILE"
    )]
    pub source_backend_config_file: Option<PathBuf>,
    #[arg(long = "target-backend-type", value_enum, env = "TARGET_BACKEND_TYPE")]
    pub target_backend_type: Option<BackendType>,
    #[arg(long = "target-backend-config", env = "TARGET_BACKEND_CONFIG")]
    pub target_backend_config: Option<String>,
    #[arg(
        long = "target-backend-config-file",
        env = "TARGET_BACKEND_CONFIG_FILE"
    )]
    pub target_backend_config_file: Option<PathBuf>,
    #[arg(long = "multi-platform", env = "MULTI_PLATFORM")]
    pub multi_platform: bool,
    #[arg(long, default_value_t = default_platform())]
    pub platform: String,
    #[arg(long = "work-dir", env = "WORK_DIR", default_value = "./output")]
    pub work_dir: PathBuf,
    #[arg(
        long = "nydus-image",
        env = "NYDUS_IMAGE",
        default_value = "nydus-image"
    )]
    pub nydus_image: PathBuf,
    #[arg(long = "nydusd", env = "NYDUSD", default_value = "nydusd")]
    pub nydusd: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct MountArgs {
    #[arg(long, env = "TARGET")]
    pub target: String,
    #[arg(long = "target-insecure", env = "TARGET_INSECURE")]
    pub target_insecure: bool,
    /// Extra PEM CA certificate file(s) trusted in addition to the system
    /// store, for registries signed by a private CA. Repeatable; ignored
    /// when `--target-insecure` is set.
    #[arg(long = "ca-cert", env = "CA_CERT", value_delimiter = ',')]
    pub ca_cert: Vec<PathBuf>,
    #[arg(long = "backend-type", value_enum, env = "BACKEND_TYPE")]
    pub backend_type: Option<BackendType>,
    #[arg(long = "backend-config", env = "BACKEND_CONFIG")]
    pub backend_config: Option<String>,
    #[arg(long = "backend-config-file", env = "BACKEND_CONFIG_FILE")]
    pub backend_config_file: Option<PathBuf>,
    #[arg(long, env = "PREFETCH")]
    pub prefetch: bool,
    #[arg(long = "mount-path", env = "MOUNT_PATH", default_value = "./image-fs")]
    pub mount_path: PathBuf,
    #[arg(long, default_value_t = default_platform())]
    pub platform: String,
    #[arg(long = "work-dir", env = "WORK_DIR", default_value = "./tmp")]
    pub work_dir: PathBuf,
    #[arg(long = "nydusd", env = "NYDUSD", default_value = "nydusd")]
    pub nydusd: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct CopyArgs {
    #[arg(long, env = "SOURCE")]
    pub source: String,
    #[arg(long, env = "TARGET")]
    pub target: Option<String>,
    #[arg(long = "source-insecure", env = "SOURCE_INSECURE")]
    pub source_insecure: bool,
    #[arg(long = "target-insecure", env = "TARGET_INSECURE")]
    pub target_insecure: bool,
    /// Extra PEM CA certificate file(s) trusted in addition to the system
    /// store, for registries signed by a private CA (applies to both source
    /// and target). Repeatable; ignored when `--*-insecure` is set.
    #[arg(long = "ca-cert", env = "CA_CERT", value_delimiter = ',')]
    pub ca_cert: Vec<PathBuf>,
    #[arg(long = "source-backend-type", value_enum, env = "SOURCE_BACKEND_TYPE")]
    pub source_backend_type: Option<BackendType>,
    #[arg(long = "source-backend-config", env = "SOURCE_BACKEND_CONFIG")]
    pub source_backend_config: Option<String>,
    #[arg(
        long = "source-backend-config-file",
        env = "SOURCE_BACKEND_CONFIG_FILE"
    )]
    pub source_backend_config_file: Option<PathBuf>,
    #[arg(long = "all-platforms")]
    pub all_platforms: bool,
    /// Target platform (defaults to the host platform). Conflicts with --all-platforms.
    #[arg(long)]
    pub platform: Option<String>,
    #[arg(long = "push-chunk-size", default_value = "0MB")]
    pub push_chunk_size: String,
    #[arg(long = "work-dir", env = "WORK_DIR", default_value = "./tmp")]
    pub work_dir: PathBuf,
    #[arg(
        long = "nydus-image",
        env = "NYDUS_IMAGE",
        default_value = "nydus-image"
    )]
    pub nydus_image: PathBuf,
}

pub fn default_platform() -> String {
    format!("linux/{}", go_arch(std::env::consts::ARCH))
}

/// Map a rustc target arch (`std::env::consts::ARCH`) to the GOARCH name used
/// in OCI image indexes. OCI/containerd platforms use Go's arch vocabulary
/// (`amd64`, `arm64`, …), not rustc's (`x86_64`, `aarch64`, …); emitting the
/// rustc name makes `select_platform` miss every multi-arch image. Unknown
/// arches pass through unchanged.
fn go_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        // rustc reports both ppc64 and ppc64le as "powerpc64"; the Linux
        // containers Nydus targets are little-endian (GOARCH ppc64le).
        "powerpc64" | "powerpc64le" => "ppc64le",
        "riscv64" => "riscv64",
        "s390x" => "s390x",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_convert_oci_ref() {
        let cli = Cli::parse_from([
            "nydusify",
            "convert",
            "--source",
            "registry.local/app:latest",
            "--target-suffix",
            "-nydus-oci-ref",
            "--oci-ref",
        ]);

        let Commands::Convert(args) = cli.command else {
            panic!("expected convert command");
        };
        assert!(args.oci_ref);
        assert_eq!(args.target_suffix.as_deref(), Some("-nydus-oci-ref"));
    }

    #[test]
    fn go_arch_maps_rustc_arch_to_goarch() {
        assert_eq!(go_arch("x86_64"), "amd64");
        assert_eq!(go_arch("aarch64"), "arm64");
        assert_eq!(go_arch("arm"), "arm");
        assert_eq!(go_arch("powerpc64"), "ppc64le");
        assert_eq!(go_arch("powerpc64le"), "ppc64le");
        assert_eq!(go_arch("riscv64"), "riscv64");
        assert_eq!(go_arch("s390x"), "s390x");
        // Unknown arches pass through untouched.
        assert_eq!(go_arch("mips64"), "mips64");
    }

    #[test]
    fn default_platform_uses_goarch_names() {
        let platform = default_platform();
        assert!(platform.starts_with("linux/"));
        // Never a rustc arch name.
        assert!(!platform.contains("x86_64"));
        assert!(!platform.contains("aarch64"));
    }
}
