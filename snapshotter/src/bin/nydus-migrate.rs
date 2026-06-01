// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! One-shot migration and recovery helper for the Rust nydus snapshotter.
//!
//! The Rust snapshotter stores metadata in fjall, while the legacy Go
//! snapshotter/containerd metadata store used bbolt. `nydus-migrate store`
//! imports the old `metadata.db` records into the new `metadata.fjall` store and
//! relocates old numeric snapshot directories to the Rust stable-key layout.

use anyhow::{Context, Result, bail};
use bbolt_rs::{Bolt, BucketApi, DbApi, TxApi};
use clap::{Parser, Subcommand, ValueEnum};
use nydus_snapshotter::overlay::snapshot_dir_name;
use nydus_snapshotter::store::{SnapshotInfo, SnapshotKind, SnapshotStore};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const LABEL_SNAPSHOT_REF: &str = "containerd.io/snapshot.ref";
const LABEL_CONFIG_REF: &str = "containerd.io/gc.ref.content.config";
const LABEL_CONTENT_SNAPSHOT_REF: &str = "containerd.io/gc.ref.snapshot.nydus";
const UNIX_TO_INTERNAL_SECONDS: i64 = (1969 * 365 + 1969 / 4 - 1969 / 100 + 1969 / 400) * 86_400;

/// Command-line arguments for the migration tool.
#[derive(Parser, Debug)]
#[command(
    name = "nydus-migrate",
    about = "Migrate and recover legacy nydus snapshotter state"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Analyze legacy config files and reject removed fscache settings.
    Config(ConfigArgs),
    /// Import legacy containerd bbolt snapshot metadata into fjall.
    Store(StoreArgs),
    /// Clear containerd content labels that point at missing nydus snapshots.
    RepairLabels(RepairLabelsArgs),
}

#[derive(Parser, Debug)]
struct ConfigArgs {
    /// Path to the legacy snapshotter TOML config.
    #[arg(long)]
    snapshotter_config: PathBuf,

    /// Path to the legacy nydusd JSON config.
    #[arg(long)]
    nydusd_config: Option<PathBuf>,

    /// Output path for the new unified TOML config.
    #[arg(long)]
    output_config: PathBuf,

    /// Actually write output files. The default is dry-run.
    #[arg(long)]
    commit: bool,
}

#[derive(Parser, Debug)]
struct StoreArgs {
    /// Path to the legacy Go/containerd bbolt metadata database.
    #[arg(long)]
    bbolt_db: PathBuf,

    /// Legacy snapshotter root. Defaults to the bbolt database parent.
    #[arg(long)]
    legacy_root: Option<PathBuf>,

    /// Output fjall metadata directory, usually <root>/metadata.fjall.
    #[arg(long)]
    output_db: PathBuf,

    /// New Rust snapshotter root. Defaults to the fjall database parent.
    #[arg(long)]
    output_root: Option<PathBuf>,

    /// Filesystem driver label to store on imported records.
    #[arg(long, value_enum, default_value_t = MigrationFsDriver::Fusedev)]
    fs_driver: MigrationFsDriver,

    /// Fail the command if any snapshot directory is missing or cannot be copied.
    #[arg(long)]
    strict: bool,

    /// Actually write fjall metadata and copy/hardlink snapshot directories.
    #[arg(long)]
    commit: bool,
}

#[derive(Parser, Debug)]
struct RepairLabelsArgs {
    /// Path to the k3s executable used to run `k3s ctr`.
    #[arg(long, default_value = "/usr/bin/k3s")]
    k3s: PathBuf,

    /// Containerd namespace to repair.
    #[arg(long, default_value = "k8s.io")]
    namespace: String,

    /// Snapshotter name to query.
    #[arg(long, default_value = "nydus")]
    snapshotter: String,

    /// Actually clear stale labels. The default is dry-run.
    #[arg(long)]
    commit: bool,
}

#[derive(Clone, Debug, ValueEnum)]
enum MigrationFsDriver {
    Fanotify,
    Fusedev,
    Blockdev,
}

impl MigrationFsDriver {
    fn as_str(&self) -> &'static str {
        match self {
            MigrationFsDriver::Fanotify => "fanotify",
            MigrationFsDriver::Fusedev => "fusedev",
            MigrationFsDriver::Blockdev => "blockdev",
        }
    }
}

#[derive(Debug)]
struct LegacySnapshot {
    key: String,
    id: u64,
    parent: Option<String>,
    kind: SnapshotKind,
    created_at: Option<i64>,
    updated_at: Option<i64>,
    labels: HashMap<String, String>,
}

#[derive(Debug, Default, Serialize)]
struct StoreMigrationReport {
    dry_run: bool,
    legacy_db: String,
    legacy_root: String,
    output_db: String,
    output_root: String,
    discovered: usize,
    importable: usize,
    imported: usize,
    skipped_existing: usize,
    copied_dirs: usize,
    reused_dirs: usize,
    missing_dirs: usize,
    errors: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
struct LabelRepairReport {
    dry_run: bool,
    namespace: String,
    snapshotter: String,
    existing_snapshots: usize,
    labels_seen: usize,
    stale_labels: usize,
    cleared: Vec<StaleContentLabel>,
}

#[derive(Clone, Debug, Serialize)]
struct StaleContentLabel {
    content: String,
    snapshot: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match Args::parse().command {
        Command::Config(args) => analyze_config(args),
        Command::Store(args) => migrate_store(args),
        Command::RepairLabels(args) => repair_labels(args),
    }
}

fn analyze_config(args: ConfigArgs) -> Result<()> {
    info!(commit = args.commit, "starting config migration analysis");

    let snapshotter_toml =
        std::fs::read_to_string(&args.snapshotter_config).with_context(|| {
            format!(
                "failed to read snapshotter config from {}",
                args.snapshotter_config.display()
            )
        })?;

    if snapshotter_toml.contains("fscache") {
        bail!(
            "legacy config references removed fscache support; use fanotify on supported kernels \
             or fusedev fallback before migrating"
        );
    }

    if let Some(nydusd_config) = args.nydusd_config.as_ref() {
        let _ = std::fs::read_to_string(nydusd_config).with_context(|| {
            format!(
                "failed to read nydusd config from {}",
                nydusd_config.display()
            )
        })?;
    }

    info!(
        output_config = %args.output_config.display(),
        "config migration analysis complete"
    );

    if args.commit {
        bail!("config file writing is not implemented yet; use k3s-config managed TOML instead");
    }

    Ok(())
}

fn migrate_store(args: StoreArgs) -> Result<()> {
    let legacy_root = args
        .legacy_root
        .clone()
        .unwrap_or_else(|| parent_or_current(&args.bbolt_db));
    let output_root = args
        .output_root
        .clone()
        .unwrap_or_else(|| parent_or_current(&args.output_db));

    info!(
        commit = args.commit,
        legacy_db = %args.bbolt_db.display(),
        output_db = %args.output_db.display(),
        "starting store migration"
    );

    let legacy_snapshots = read_legacy_snapshots(&args.bbolt_db)?;
    let store = SnapshotStore::open(&args.output_db)?;
    let mut report = StoreMigrationReport {
        dry_run: !args.commit,
        legacy_db: args.bbolt_db.display().to_string(),
        legacy_root: legacy_root.display().to_string(),
        output_db: args.output_db.display().to_string(),
        output_root: output_root.display().to_string(),
        discovered: legacy_snapshots.len(),
        ..StoreMigrationReport::default()
    };

    for snapshot in legacy_snapshots {
        let source_dir = legacy_root.join("snapshots").join(snapshot.id.to_string());
        let target_dir = output_root
            .join("snapshots")
            .join(snapshot_dir_name(&snapshot.key));

        let target_available = ensure_snapshot_dir(
            &snapshot,
            &source_dir,
            &target_dir,
            args.commit,
            &mut report,
        );

        if let Err(e) = target_available {
            report.errors.push(format!(
                "{}: failed to prepare snapshot directory: {e:#}",
                snapshot.key
            ));
            continue;
        }
        if !target_available? {
            continue;
        }

        if store.exists(&snapshot.key)? {
            report.skipped_existing += 1;
            continue;
        }

        let now = now_unix();
        let info = SnapshotInfo {
            key: snapshot.key.clone(),
            parent: snapshot.parent.clone(),
            kind: snapshot.kind.as_str().to_string(),
            fs_driver: args.fs_driver.as_str().to_string(),
            image_ref: image_ref(&snapshot.labels).map(str::to_string),
            created_at: snapshot.created_at.unwrap_or(now),
            updated_at: snapshot.updated_at.or(snapshot.created_at).unwrap_or(now),
            labels: snapshot.labels.clone(),
        };

        if args.commit {
            if let Err(e) = store.import_snapshot(info) {
                report.errors.push(format!(
                    "{}: failed to import metadata: {e:#}",
                    snapshot.key
                ));
                continue;
            }
            report.imported += 1;
        } else {
            report.importable += 1;
        }
    }

    let rendered = serde_json::to_string_pretty(&report)?;
    println!("{rendered}");

    if args.strict && !report.errors.is_empty() {
        bail!(
            "store migration completed with {} error(s) in strict mode",
            report.errors.len()
        );
    }

    Ok(())
}

fn repair_labels(args: RepairLabelsArgs) -> Result<()> {
    info!(
        namespace = args.namespace,
        snapshotter = args.snapshotter,
        commit = args.commit,
        "starting content label repair"
    );

    let snapshot_output = run_k3s_ctr(
        &args.k3s,
        &[
            "-n",
            &args.namespace,
            "snapshots",
            "--snapshotter",
            &args.snapshotter,
            "ls",
        ],
    )?;
    let existing_snapshots = parse_snapshot_keys(&snapshot_output);

    let content_output = run_k3s_ctr(&args.k3s, &["-n", &args.namespace, "content", "ls"])?;
    let mut seen = 0usize;
    let mut stale = Vec::new();
    for line in content_output.lines() {
        let Some((content, snapshot)) = parse_content_snapshot_label(line) else {
            continue;
        };
        seen += 1;
        if !existing_snapshots.contains(snapshot) {
            stale.push(StaleContentLabel {
                content: content.to_string(),
                snapshot: snapshot.to_string(),
            });
        }
    }

    if args.commit {
        for label in &stale {
            run_k3s_ctr(
                &args.k3s,
                &[
                    "-n",
                    &args.namespace,
                    "content",
                    "label",
                    &label.content,
                    &format!("{LABEL_CONTENT_SNAPSHOT_REF}="),
                ],
            )?;
        }
    }

    let report = LabelRepairReport {
        dry_run: !args.commit,
        namespace: args.namespace,
        snapshotter: args.snapshotter,
        existing_snapshots: existing_snapshots.len(),
        labels_seen: seen,
        stale_labels: stale.len(),
        cleared: stale,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);

    Ok(())
}

fn run_k3s_ctr(k3s: &Path, args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new(k3s)
        .arg("ctr")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {} ctr", k3s.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "{} ctr {} failed with status {}: {}{}",
            k3s.display(),
            args.join(" "),
            output.status,
            stdout,
            stderr
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn parse_snapshot_keys(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|key| *key != "KEY")
        .map(str::to_string)
        .collect()
}

fn parse_content_snapshot_label(line: &str) -> Option<(&str, &str)> {
    let content = line.split_whitespace().next()?;
    if !content.starts_with("sha256:") {
        return None;
    }

    let label = format!("{LABEL_CONTENT_SNAPSHOT_REF}=");
    let snapshot_start = line.find(&label)? + label.len();
    let snapshot = line[snapshot_start..]
        .split([',', ' ', '\t'])
        .next()
        .filter(|value| value.starts_with("sha256:"))?;

    Some((content, snapshot))
}

fn read_legacy_snapshots(path: &Path) -> Result<Vec<LegacySnapshot>> {
    let db = Bolt::open_ro(path).with_context(|| {
        format!(
            "failed to open legacy bbolt snapshot metadata at {}",
            path.display()
        )
    })?;
    let tx = db
        .begin()
        .context("failed to begin bbolt read transaction")?;
    let v1 = tx
        .bucket("v1")
        .context("legacy metadata is missing v1 bucket")?;
    let snapshots = v1
        .bucket("snapshots")
        .context("legacy metadata is missing v1/snapshots bucket")?;

    let mut legacy_snapshots = Vec::new();
    for (key_bytes, snapshot_bucket) in snapshots.iter_buckets() {
        let key = String::from_utf8_lossy(key_bytes).into_owned();
        let id = read_uvarint(
            snapshot_bucket
                .get("id")
                .with_context(|| format!("snapshot {key} is missing id"))?,
        )
        .with_context(|| format!("snapshot {key} has invalid id"))?;
        let kind = SnapshotKind::from_containerd_kind(
            *snapshot_bucket
                .get("kind")
                .and_then(|value| value.first())
                .with_context(|| format!("snapshot {key} is missing kind"))?,
        )
        .with_context(|| format!("snapshot {key} has unsupported kind"))?;
        let parent = snapshot_bucket
            .get("parent")
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .filter(|value| !value.is_empty());
        let labels = read_labels(&snapshot_bucket);
        let created_at = read_go_time_unix(snapshot_bucket.get("createdat"));
        let updated_at = read_go_time_unix(snapshot_bucket.get("updatedat"));

        legacy_snapshots.push(LegacySnapshot {
            key,
            id,
            parent,
            kind,
            created_at,
            updated_at,
            labels,
        });
    }

    Ok(legacy_snapshots)
}

fn read_labels<'tx, B: BucketApi<'tx>>(snapshot_bucket: &B) -> HashMap<String, String> {
    let mut labels = HashMap::new();
    if let Some(labels_bucket) = snapshot_bucket.bucket("labels") {
        for (key, value) in labels_bucket.iter_entries() {
            labels.insert(
                String::from_utf8_lossy(key).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            );
        }
    }
    labels
}

fn ensure_snapshot_dir(
    snapshot: &LegacySnapshot,
    source_dir: &Path,
    target_dir: &Path,
    commit: bool,
    report: &mut StoreMigrationReport,
) -> Result<bool> {
    if target_dir.join("fs").is_dir() || target_dir.is_dir() {
        report.reused_dirs += 1;
        return Ok(true);
    }

    if !source_dir.is_dir() {
        report.missing_dirs += 1;
        let message = format!(
            "{}: legacy snapshot directory {} is missing",
            snapshot.key,
            source_dir.display()
        );
        warn!("{message}");
        report.errors.push(message);
        return Ok(false);
    }

    if commit {
        copy_dir_recursive(source_dir, target_dir).with_context(|| {
            format!(
                "failed to copy legacy snapshot directory {} to {}",
                source_dir.display(),
                target_dir.display()
            )
        })?;
        report.copied_dirs += 1;
    }

    Ok(true)
}

fn copy_dir_recursive(source: &Path, target: &Path) -> Result<()> {
    if target.exists() {
        bail!("target path {} already exists", target.display());
    }

    let metadata = std::fs::symlink_metadata(source)
        .with_context(|| format!("failed to stat {}", source.display()))?;
    let file_type = metadata.file_type();

    if file_type.is_symlink() {
        copy_symlink(source, target)?;
    } else if file_type.is_dir() {
        std::fs::create_dir_all(target)
            .with_context(|| format!("failed to create {}", target.display()))?;
        for entry in std::fs::read_dir(source)
            .with_context(|| format!("failed to read directory {}", source.display()))?
        {
            let entry = entry?;
            copy_dir_recursive(&entry.path(), &target.join(entry.file_name()))?;
        }
    } else if file_type.is_file() {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        if std::fs::hard_link(source, target).is_err() {
            std::fs::copy(source, target).with_context(|| {
                format!(
                    "failed to copy file {} to {}",
                    source.display(),
                    target.display()
                )
            })?;
        }
    } else {
        bail!("unsupported file type at {}", source.display());
    }

    Ok(())
}

#[cfg(unix)]
fn copy_symlink(source: &Path, target: &Path) -> Result<()> {
    let link_target = std::fs::read_link(source)
        .with_context(|| format!("failed to read symlink {}", source.display()))?;
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::os::unix::fs::symlink(&link_target, target).with_context(|| {
        format!(
            "failed to create symlink {} -> {}",
            target.display(),
            link_target.display()
        )
    })
}

#[cfg(not(unix))]
fn copy_symlink(source: &Path, _target: &Path) -> Result<()> {
    bail!(
        "cannot copy symlink {} on non-Unix platform",
        source.display()
    )
}

fn read_uvarint(bytes: &[u8]) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte < 0x80 {
            if index > 9 || (index == 9 && byte > 1) {
                bail!("uvarint overflows u64");
            }
            return Ok(value | (u64::from(byte) << shift));
        }
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
    }

    bail!("truncated uvarint")
}

fn read_go_time_unix(bytes: Option<&[u8]>) -> Option<i64> {
    let bytes = bytes?;
    if bytes.len() < 15 || !matches!(bytes[0], 1 | 2) {
        return None;
    }
    let sec = i64::from_be_bytes(bytes[1..9].try_into().ok()?);
    Some(sec.saturating_sub(UNIX_TO_INTERNAL_SECONDS))
}

fn image_ref(labels: &HashMap<String, String>) -> Option<&str> {
    labels
        .get(LABEL_SNAPSHOT_REF)
        .or_else(|| labels.get(LABEL_CONFIG_REF))
        .map(String::as_str)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn parent_or_current(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_uvarint() {
        assert_eq!(read_uvarint(&[0]).unwrap(), 0);
        assert_eq!(read_uvarint(&[172, 2]).unwrap(), 300);
        assert!(read_uvarint(&[128]).is_err());
    }

    #[test]
    fn decodes_go_time_unix_seconds() {
        let unix = 1_700_000_000i64;
        let internal = unix + UNIX_TO_INTERNAL_SECONDS;
        let mut encoded = Vec::new();
        encoded.push(1);
        encoded.extend_from_slice(&internal.to_be_bytes());
        encoded.extend_from_slice(&0u32.to_be_bytes());
        encoded.extend_from_slice(&(-1i16).to_be_bytes());
        assert_eq!(read_go_time_unix(Some(&encoded)), Some(unix));
    }

    #[test]
    fn parses_content_snapshot_label() {
        let line = "sha256:140453636766f359e6d31e1ab336c92b9acd74c40222f421ba5200276ce95bda 973B 22 hours containerd.io/distribution.source.docker.io=curlimages/curl,containerd.io/gc.ref.snapshot.nydus=sha256:9ae80fcfea09928f4923fed8d049ac0c07768f066aa0af8cefaa113feede31a0";

        assert_eq!(
            parse_content_snapshot_label(line),
            Some((
                "sha256:140453636766f359e6d31e1ab336c92b9acd74c40222f421ba5200276ce95bda",
                "sha256:9ae80fcfea09928f4923fed8d049ac0c07768f066aa0af8cefaa113feede31a0"
            ))
        );
    }
}
