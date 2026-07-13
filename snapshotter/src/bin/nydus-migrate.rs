// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! One-shot migration and recovery helper for the Rust nydus snapshotter.
//!
//! The Rust snapshotter stores metadata in fjall, while the legacy Go
//! snapshotter/containerd metadata store used bbolt. `nydus-migrate store`
//! imports the old `metadata.db` records into the new `metadata.fjall` store and
//! relocates old numeric snapshot directories to the Rust stable-key layout.

#![deny(warnings)]
#![warn(clippy::all)]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use nydus_snapshotter::migrate::StoreMigrationParams;
use nydus_snapshotter::store::SnapshotStore;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use tracing::info;

const LABEL_CONTENT_SNAPSHOT_REF: &str = "containerd.io/gc.ref.snapshot.nydus";

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
    /// Delete snapshot records from containerd's metadata bolt that the
    /// nydus snapshotter no longer holds (drifts in either direction —
    /// typically containerd remembering a snapshot whose fjall record was
    /// lost on an unclean shutdown — wedge pod creation with `snapshot ...
    /// does not exist` or `target snapshot ... already exists`).
    ReconcileSnapshots(ReconcileSnapshotsArgs),
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
struct ReconcileSnapshotsArgs {
    /// Path to containerd's main metadata bolt database — the one whose
    /// `v1/<ns>/snapshots/<snapshotter>/` bucket diverges from the
    /// snapshotter's fjall store when an unclean shutdown loses the
    /// in-memory snapshot batch. Default targets a k3s-managed containerd.
    #[arg(
        long,
        default_value = "/var/lib/rancher/k3s/agent/containerd/io.containerd.metadata.v1.bolt/meta.db"
    )]
    containerd_meta_db: PathBuf,

    /// Path to the snapshotter's fjall directory — the same store
    /// `containerd-nydus` opens. Source of truth: if this store does not
    /// have a key that containerd's bolt does, the bolt record is stale.
    #[arg(
        long,
        default_value = "/var/lib/rancher/k3s/agent/containerd/nydus/snapshotter/metadata.fjall"
    )]
    snapshotter_store: PathBuf,

    /// Containerd namespace to scan.
    #[arg(long, default_value = "k8s.io")]
    namespace: String,

    /// Snapshotter name inside containerd's bolt — the bucket immediately
    /// under `v1/<namespace>/snapshots/`.
    #[arg(long, default_value = "nydus")]
    snapshotter: String,

    /// Actually delete stale records (and clean up parent->child links).
    /// Default is dry-run. Requires both `k3s` (so containerd releases its
    /// bolt write-lock) and `nydus-snapshotter` (so fjall opens
    /// single-writer) to be stopped while this runs.
    #[arg(long)]
    commit: bool,

    /// Permit operating against a fjall store that contains zero snapshots.
    /// By default the tool refuses, because an empty store makes every
    /// containerd bolt record look stale — a typo'd `--snapshotter-store`
    /// (fjall silently creates the directory on open) would otherwise wipe
    /// the entire snapshotter section of containerd's metadata on
    /// `--commit`. Only pass this when you genuinely have a fresh fjall
    /// store and want to clear matching containerd records.
    #[arg(long)]
    allow_empty_snapshotter_store: bool,
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

#[derive(Debug, Default, Serialize)]
struct ReconcileSnapshotsReport {
    dry_run: bool,
    containerd_meta_db: String,
    snapshotter_store: String,
    namespace: String,
    snapshotter: String,
    /// Number of snapshot buckets containerd's bolt holds for this
    /// snapshotter — the universe we walked.
    containerd_snapshots: usize,
    /// Number of those that also exist in the snapshotter's fjall store.
    consistent: usize,
    /// Number whose key the snapshotter does not have. These get deleted on
    /// `--commit`.
    stale: usize,
    /// Stale snapshot records the tool would not delete because a child of
    /// theirs still resolves in the snapshotter. Surfaces a true bolt/fjall
    /// inconsistency we can't safely auto-resolve; the operator needs to
    /// inspect.
    stale_with_live_child: Vec<StaleWithLiveChild>,
    /// Snapshot keys whose fjall liveness could not be determined because
    /// `SnapshotStore::exists` failed (fjall I/O error). These are
    /// conservatively treated as live so the bolt record is preserved;
    /// surfaced here so the operator can fix the underlying fjall problem
    /// before re-running.
    undetermined: Vec<UndeterminedKey>,
    /// Stale snapshot keys deleted (or that would be deleted on `--commit`).
    cleared: Vec<String>,
    errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct StaleWithLiveChild {
    stale_parent: String,
    live_child: String,
}

#[derive(Clone, Debug, Serialize)]
struct UndeterminedKey {
    key: String,
    error: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match Args::parse().command {
        Command::Config(args) => analyze_config(args),
        Command::Store(args) => migrate_store(args),
        Command::RepairLabels(args) => repair_labels(args),
        Command::ReconcileSnapshots(args) => reconcile_snapshots(args),
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

    // Validate the legacy bbolt db BEFORE opening the destination fjall
    // store. `SnapshotStore::open` creates `metadata.fjall` on first touch
    // (fjall materializes the directory eagerly), so opening it first would
    // leave a stray empty output directory behind when `--bbolt-db` turns
    // out to be missing or unreadable — the old Go-era bin read bbolt first
    // and failed fast with no side effect; keep that property here.
    nydus_snapshotter::migrate::validate_legacy_bbolt_db(&args.bbolt_db).with_context(|| {
        format!(
            "legacy bbolt db {} is not a readable bbolt database",
            args.bbolt_db.display()
        )
    })?;

    // The import core lives in `nydus_snapshotter::migrate` so the
    // snapshotter can run the same migration automatically at startup; this
    // subcommand keeps the operator-facing dry-run/commit/strict semantics
    // and the JSON report.
    let store = SnapshotStore::open(&args.output_db)?;
    let report = nydus_snapshotter::migrate::migrate_store(
        &store,
        &StoreMigrationParams {
            bbolt_db: &args.bbolt_db,
            legacy_root: &legacy_root,
            output_db: &args.output_db,
            output_root: &output_root,
            fs_driver: args.fs_driver.as_str(),
            commit: args.commit,
        },
    )?;

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

/// Walk containerd's metadata bolt for `<namespace>/snapshots/<snapshotter>/`
/// and delete records the snapshotter's fjall store no longer holds. The
/// snapshotter store is authoritative: anything in containerd's bolt that
/// the snapshotter doesn't have can't be backed by an on-disk snapshot
/// directory anyway (the snapshotter is the only writer for both), so the
/// bolt record is stale.
///
/// Preconditions (enforced by docs, not by the tool — the tool just fails
/// loudly if bolt can't be opened RW or fjall can't take the single-writer
/// lock):
///
///   * `--commit` requires `k3s` (and therefore containerd) to be stopped,
///     since bolt holds an exclusive flock while containerd runs.
///   * Likewise it requires `nydus-snapshotter` to be stopped, because
///     fjall's `SingleWriterTxDatabase` also takes an exclusive lock.
///
/// The deletion mirrors what `core/metadata/snapshot.go::Remove` does in
/// containerd itself: read the `parent` field, scrub the entry from the
/// parent's `children` sub-bucket, then delete the bucket. The only extra
/// piece is iterating until a fixed point so a stale leaf gets deleted
/// before its (also-stale) parent — otherwise we'd hit containerd's own
/// "cannot remove snapshot with child" invariant.
fn reconcile_snapshots(args: ReconcileSnapshotsArgs) -> Result<()> {
    use bbolt_rs::{BucketApi, BucketRwApi, DbApi, DbRwAPI, TxApi, TxRwApi, TxRwRefApi};

    info!(
        namespace = args.namespace,
        snapshotter = args.snapshotter,
        commit = args.commit,
        "starting snapshot reconciliation"
    );

    // Refuse to let fjall auto-create an empty store from a typo'd path.
    // `SnapshotStore::open` does `create_dir_all` + materialise — without
    // this guard, a wrong `--snapshotter-store` produces a brand-new empty
    // store whose missing keys would classify every containerd record as
    // stale.
    if !args.snapshotter_store.exists() {
        bail!(
            "snapshotter fjall store {} does not exist; refusing to auto-create \
             (a typo here would classify every containerd record as stale). \
             Pass the correct path, or pre-create the directory only if you \
             know what you're doing.",
            args.snapshotter_store.display()
        );
    }

    let store = SnapshotStore::open(&args.snapshotter_store).with_context(|| {
        format!(
            "failed to open snapshotter fjall store at {} \
             (is nydus-snapshotter still running, or did you point at the wrong fjall directory?)",
            args.snapshotter_store.display()
        )
    })?;

    // Final safeguard: an empty store makes every containerd record look
    // stale. Even when the path existed, it may have been pre-created
    // empty (mount-not-yet-up, fresh nydus install) — bail unless the
    // operator explicitly opted in.
    let store_snapshot_count = store
        .list()
        .context("failed to list fjall snapshots to verify the store isn't empty")?
        .len();
    if store_snapshot_count == 0 && !args.allow_empty_snapshotter_store {
        bail!(
            "snapshotter fjall store {} is empty; refusing to reconcile against it \
             because every containerd record would look stale. Re-run with \
             `--allow-empty-snapshotter-store` if this is intentional.",
            args.snapshotter_store.display()
        );
    }

    let mut report = ReconcileSnapshotsReport {
        dry_run: !args.commit,
        containerd_meta_db: args.containerd_meta_db.display().to_string(),
        snapshotter_store: args.snapshotter_store.display().to_string(),
        namespace: args.namespace.clone(),
        snapshotter: args.snapshotter.clone(),
        ..Default::default()
    };

    // Read-only first pass: walk every snapshot under
    // `v1/<namespace>/snapshots/<snapshotter>/`, ask the fjall store
    // whether it agrees, and capture each record's parent so the write
    // pass can scrub the matching `parent.children/<key>` entry the way
    // containerd's own `core/metadata/snapshot.go::Remove` does. We do
    // this even in dry-run mode so the JSON report shows exactly what
    // `--commit` would touch.
    let mut snapshots_total: usize = 0;
    let mut stale: BTreeSet<String> = BTreeSet::new();
    let mut children_of: HashMap<String, Vec<String>> = HashMap::new();
    let mut undetermined: Vec<UndeterminedKey> = Vec::new();
    let mut bucket_present = true;
    {
        let db = bbolt_rs::Bolt::open_ro(&args.containerd_meta_db).with_context(|| {
            format!(
                "failed to open containerd metadata bolt at {} read-only",
                args.containerd_meta_db.display()
            )
        })?;
        let tx = db.begin().context("begin read-only bbolt transaction")?;
        let walked: Option<()> = (|| {
            let v1 = tx.bucket("v1")?;
            let ns = v1.bucket(args.namespace.as_str())?;
            let snapshots = ns.bucket("snapshots")?;
            let snapshotter_bucket = snapshots.bucket(args.snapshotter.as_str())?;
            for (key_bytes, snapshot_bucket) in snapshotter_bucket.iter_buckets() {
                let key = String::from_utf8_lossy(key_bytes).into_owned();
                let parent = snapshot_bucket
                    .get("parent")
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .filter(|v| !v.is_empty());
                if let Some(p) = &parent {
                    children_of.entry(p.clone()).or_default().push(key.clone());
                }
                // Only a definite `Ok(false)` from fjall counts as stale.
                // `Err(_)` means we couldn't determine liveness (transient
                // fjall I/O error) — treat as live so we never destroy a
                // bolt record on the basis of an indeterminate read.
                match store.exists(&key) {
                    Ok(true) => {}
                    Ok(false) => {
                        stale.insert(key.clone());
                    }
                    Err(e) => {
                        undetermined.push(UndeterminedKey {
                            key: key.clone(),
                            error: format!("{e:#}"),
                        });
                    }
                }
                snapshots_total += 1;
            }
            Some(())
        })();
        if walked.is_none() {
            bucket_present = false;
        }
    }

    if !bucket_present {
        report.errors.push(format!(
            "containerd metadata bolt has no `v1/{}/snapshots/{}` bucket — nothing to reconcile",
            args.namespace, args.snapshotter
        ));
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    report.containerd_snapshots = snapshots_total;
    report.stale = stale.len();
    report.consistent = snapshots_total - stale.len() - undetermined.len();
    if !undetermined.is_empty() {
        report.errors.push(format!(
            "{} snapshot key(s) had indeterminate fjall liveness; preserving their bolt records",
            undetermined.len()
        ));
        report.undetermined = undetermined;
    }

    // Refuse to delete any stale snapshot whose `children/` sub-bucket
    // contains an entry that is NOT stale — that would orphan the still-
    // live child and quietly break it. Surface those in the report
    // instead and let the operator decide.
    for stale_key in &stale {
        if let Some(children) = children_of.get(stale_key) {
            for child in children {
                if !stale.contains(child) {
                    report.stale_with_live_child.push(StaleWithLiveChild {
                        stale_parent: stale_key.clone(),
                        live_child: child.clone(),
                    });
                }
            }
        }
    }
    if !report.stale_with_live_child.is_empty() {
        report.errors.push(format!(
            "{} stale parent record(s) have at least one live child; refusing to delete those",
            report.stale_with_live_child.len()
        ));
    }

    // Stale-with-live-child is excluded so we never orphan a live child.
    let excluded: BTreeSet<&str> = report
        .stale_with_live_child
        .iter()
        .map(|s| s.stale_parent.as_str())
        .collect();
    let mut deletable: BTreeSet<String> = stale
        .iter()
        .filter(|k| !excluded.contains(k.as_str()))
        .cloned()
        .collect();

    if !args.commit {
        report.cleared = deletable.into_iter().collect();
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Commit path. We open the bolt RW, walk in passes that each delete
    // every stale key whose stale dependants are already gone — that
    // matches containerd's own remove ordering and avoids hitting the
    // "cannot remove snapshot with child" invariant inside our own
    // transaction. The navigation is inlined per delete because bbolt-rs's
    // `BucketRwApi` returns a borrow tied to its receiver, and threading
    // a re-usable bucket handle through the loop fights the borrow
    // checker harder than it's worth here.
    let mut db = bbolt_rs::Bolt::open(&args.containerd_meta_db).with_context(|| {
        format!(
            "failed to open containerd metadata bolt at {} for writing (is k3s still running?)",
            args.containerd_meta_db.display()
        )
    })?;
    let mut tx = db
        .begin_rw()
        .context("begin read-write bbolt transaction")?;

    let mut cleared: Vec<String> = Vec::new();
    while !deletable.is_empty() {
        let mut progress = false;
        let pass: Vec<String> = deletable.iter().cloned().collect();
        for key in pass {
            // Defer until our stale dependants are gone.
            let pending_child = children_of
                .get(&key)
                .map(|cs| cs.iter().any(|c| deletable.contains(c)))
                .unwrap_or(false);
            if pending_child {
                continue;
            }

            // First read the parent field so we can scrub the child link.
            let parent_key = {
                let v1 = tx
                    .bucket("v1")
                    .ok_or_else(|| anyhow::anyhow!("v1 bucket vanished mid-transaction"))?;
                let ns = v1.bucket(args.namespace.as_str()).ok_or_else(|| {
                    anyhow::anyhow!("v1/{} bucket vanished mid-transaction", args.namespace)
                })?;
                let snapshots = ns.bucket("snapshots").ok_or_else(|| {
                    anyhow::anyhow!("v1/{}/snapshots vanished mid-transaction", args.namespace)
                })?;
                let snapshotter_bucket =
                    snapshots.bucket(args.snapshotter.as_str()).ok_or_else(|| {
                        anyhow::anyhow!(
                            "v1/{}/snapshots/{} vanished mid-transaction",
                            args.namespace,
                            args.snapshotter
                        )
                    })?;
                let sbkt = snapshotter_bucket.bucket(&key).ok_or_else(|| {
                    anyhow::anyhow!("stale snapshot {key} vanished from bolt before delete")
                })?;
                sbkt.get("parent")
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .filter(|v| !v.is_empty())
            };

            // Scrub the child link in the parent's `children/` sub-bucket,
            // then delete the stale snapshot's own bucket. Same write path
            // containerd's own Remove takes, just deferred so we never
            // skip the precondition the way `--force` would.
            {
                let mut v1 = tx
                    .bucket_mut("v1")
                    .ok_or_else(|| anyhow::anyhow!("v1 bucket vanished mid-transaction"))?;
                let mut ns = v1.bucket_mut(args.namespace.as_str()).ok_or_else(|| {
                    anyhow::anyhow!("v1/{} bucket vanished mid-transaction", args.namespace)
                })?;
                let mut snapshots = ns.bucket_mut("snapshots").ok_or_else(|| {
                    anyhow::anyhow!("v1/{}/snapshots vanished mid-transaction", args.namespace)
                })?;
                let mut snapshotter_bucket = snapshots
                    .bucket_mut(args.snapshotter.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "v1/{}/snapshots/{} vanished mid-transaction",
                            args.namespace,
                            args.snapshotter
                        )
                    })?;

                if let Some(parent) = parent_key
                    && let Some(mut pbkt) = snapshotter_bucket.bucket_mut(&parent)
                    && let Some(mut cbkt) = pbkt.bucket_mut("children")
                {
                    // Tolerate the child entry already being gone.
                    let _ = cbkt.delete(&key);
                }
                snapshotter_bucket.delete_bucket(&key).with_context(|| {
                    format!("failed to delete stale snapshot bucket {key} from containerd bolt")
                })?;
            }

            cleared.push(key.clone());
            deletable.remove(&key);
            progress = true;
        }

        if !progress {
            return Err(anyhow::anyhow!(
                "reconcile-snapshots stuck with {} undeletable keys; bailing without commit (no records changed)",
                deletable.len()
            ));
        }
    }

    tx.commit()
        .context("commit reconcile-snapshots bbolt transaction")?;

    report.cleared = cleared;
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

fn parent_or_current(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn migrate_store_bad_bbolt_db_does_not_create_output_dir() {
        let dir = tempdir().unwrap();
        let bbolt_db = dir.path().join("does-not-exist.db");
        let output_db = dir.path().join("metadata.fjall");

        let args = StoreArgs {
            bbolt_db,
            legacy_root: None,
            output_db: output_db.clone(),
            output_root: None,
            fs_driver: MigrationFsDriver::Fusedev,
            strict: false,
            commit: false,
        };

        assert!(migrate_store(args).is_err());
        assert!(
            !output_db.exists(),
            "a bad --bbolt-db must not leave an empty metadata.fjall directory behind"
        );
    }

    #[test]
    fn migrate_store_garbage_bbolt_db_does_not_create_output_dir() {
        let dir = tempdir().unwrap();
        let bbolt_db = dir.path().join("garbage.db");
        std::fs::write(&bbolt_db, b"not a bolt database").unwrap();
        let output_db = dir.path().join("metadata.fjall");

        let args = StoreArgs {
            bbolt_db,
            legacy_root: None,
            output_db: output_db.clone(),
            output_root: None,
            fs_driver: MigrationFsDriver::Fusedev,
            strict: false,
            commit: true,
        };

        assert!(migrate_store(args).is_err());
        assert!(
            !output_db.exists(),
            "a garbage --bbolt-db must not leave an empty metadata.fjall directory behind"
        );
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
