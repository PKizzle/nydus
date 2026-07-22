// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Node-local acceleration: convert a standard OCI image's gzip layers into a RAFS v6 + zran
//! artifact **locally**, with no registry push and no image-tag change, then serve it on demand
//! through the fanotify pre-content path.
//!
//! The data model (verified end-to-end): in OCI a gzip layer's digest *is* the sha256 of its
//! compressed bytes, and that is exactly the id nydus uses for the referenced zran data blob and
//! the key containerd's content store files it under. So a `localfs` backend pointed at the content
//! store serves the layers byte-for-byte with zero re-download; the only new artifacts are the
//! merged bootstrap and the tiny per-layer zran index blobs, generated here.
//!
//! Pipeline (each step is a verified `nydus-image` invocation — see
//! `misc/fanotify/zran-multilayer-test.sh`):
//!   1. for each gzip layer:  `nydus-image create --type targz-ref --fs-version 6 -B <b_i> -D <d_i> <layer>`
//!   2. merge:                `nydus-image merge -B <bootstrap> --original-blob-ids <d0,d1,..> <b0> <b1> ..`
//!   3. stage a `localfs` backend dir holding the gzip layers (symlinked from the content store,
//!      keyed by digest) plus the per-layer zran index blobs.
//!
//! The resulting `(bootstrap, backend_dir, work_dir)` feeds a fanotify `BlobCacheEntry`; the
//! `FanotifyHandler` self-stages the EROFS device files and serves reads on demand.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// A gzip layer of the source image as it exists in containerd's content store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GzipLayer {
    /// OCI digest of the gzip layer (`sha256:...` or bare hex). This is also the nydus zran data
    /// blob id and the content-store key.
    pub digest: String,
    /// Path to the gzip layer blob in the content store.
    pub path: PathBuf,
}

impl GzipLayer {
    /// Bare lowercase hex of the digest (strips an optional `sha256:` / `algo:` prefix), which is
    /// how nydus names the data blob and how the localfs backend files it.
    pub fn blob_id(&self) -> &str {
        match self.digest.split_once(':') {
            Some((_algo, hex)) => hex,
            None => &self.digest,
        }
    }
}

/// Low-priority scheduling class for background conversion work, resolved per OS so the same
/// request maps to the right primitive (`ionice` + `nice` on Linux, `taskpolicy` on macOS).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedClass {
    /// Run at normal priority.
    Normal,
    /// Idle CPU (`nice`) and, where available, idle I/O priority.
    Idle,
}

impl SchedClass {
    /// Build the command prefix (program + leading args) that wraps the real command to lower its
    /// priority on the current OS. Returns `None` when no wrapper is needed/available, in which
    /// case the caller runs the program directly.
    ///
    /// * Linux: `ionice -c 3 nice -n <nice>` (idle I/O + low CPU).
    /// * macOS: `taskpolicy -c utility` (no `ionice`; `taskpolicy` is the closest analogue).
    /// * other: no wrapper.
    pub fn command_prefix(self, nice: i32, os: &str) -> Option<Vec<OsString>> {
        if self == SchedClass::Normal {
            return None;
        }
        let nice = nice.clamp(0, 19).to_string();
        match os {
            "linux" => Some(vec![
                "ionice".into(),
                "-c".into(),
                "3".into(),
                "nice".into(),
                "-n".into(),
                nice.into(),
            ]),
            "macos" => Some(vec!["taskpolicy".into(), "-c".into(), "utility".into()]),
            _ => None,
        }
    }
}

/// Configuration for a node-local conversion.
#[derive(Clone, Debug)]
pub struct LocalAccelConfig {
    /// Path to the `nydus-image` binary.
    pub nydus_image: PathBuf,
    /// Per-image working directory (bootstrap + index blobs + backend symlinks are staged here).
    pub work_dir: PathBuf,
    /// Scheduling class for the (CPU-heavy) conversion subprocesses.
    pub sched: SchedClass,
    /// `nice` level when `sched` is `Idle`.
    pub nice: i32,
}

/// Result of a node-local conversion, ready to feed a fanotify `BlobCacheEntry`
/// and uploaded as a content-store sidecar by the auto-zran worker.
///
/// Serializable so the two-stage auto-accel pipeline can persist a base
/// artifact (`convert` with empty prefetch) to `work_dir/artifact.json` and
/// reload it on stage 2 to run `optimize_existing` without re-running
/// create/merge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeLocalArtifact {
    /// Merged RAFS v6 bootstrap (the fanotify staging dir's `bootstrap`). When
    /// `prefetch_files` was non-empty this is the OPTIMIZED bootstrap produced
    /// by `nydus-image optimize`, with prefetch hints baked in.
    pub bootstrap: PathBuf,
    /// `localfs` backend directory holding the gzip layers (symlinked, by
    /// blob_id) and the per-layer zran index blobs (real files, by blob_id).
    pub backend_dir: PathBuf,
    /// Blob-cache working directory (also the fanotify staging dir); equals
    /// the parent of `bootstrap`.
    pub work_dir: PathBuf,
    /// Original gzip-layer blob ids, lower→upper, in device-table order.
    pub layer_blob_ids: Vec<String>,
    /// Per-layer zran index blob ids (one entry per gzip layer, same order as
    /// `layer_blob_ids`). Each blob lives at `backend_dir.join(id)`. `None`
    /// marks a layer with no data chunks (directory/whiteout/metadata-only
    /// tars): `nydus-image create` emits no zran blob for those, the merged
    /// blob table never references them, and only their namespace entries
    /// survive into the merged bootstrap.
    pub zran_index_blob_ids: Vec<Option<String>>,
    /// Optional prefetch blob id (only present when `convert` was called with
    /// non-empty `prefetch_files`). The blob holds the chunks listed by the
    /// prefetch hint, packed for one-shot warm-up; it lives at
    /// `backend_dir.join(id)`.
    pub prefetch_blob_id: Option<String>,
}

/// Build the args for a per-layer `nydus-image create --type targz-ref` conversion.
///
/// `bootstrap_out` receives the per-layer bootstrap; `blob_out_dir` receives the zran index blob.
pub fn targz_ref_args(layer: &Path, bootstrap_out: &Path, blob_out_dir: &Path) -> Vec<OsString> {
    vec![
        "create".into(),
        "--type".into(),
        "targz-ref".into(),
        "--fs-version".into(),
        "6".into(),
        "-B".into(),
        bootstrap_out.into(),
        "-D".into(),
        blob_out_dir.into(),
        layer.into(),
    ]
}

/// Build the args for `nydus-image merge` of the per-layer bootstraps (lower→upper) into one
/// overlaid bootstrap. `original_blob_ids` are the gzip-layer digests in the same order.
pub fn merge_args(
    bootstrap_out: &Path,
    original_blob_ids: &[String],
    layer_bootstraps: &[PathBuf],
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "merge".into(),
        "-B".into(),
        bootstrap_out.into(),
        "--original-blob-ids".into(),
        original_blob_ids.join(",").into(),
    ];
    for b in layer_bootstraps {
        args.push(b.into());
    }
    args
}

/// Wrap a program+args with the scheduling-class prefix for the current OS.
fn build_command(prog: &Path, args: &[OsString], sched: SchedClass, nice: i32) -> Command {
    match sched.command_prefix(nice, std::env::consts::OS) {
        Some(prefix) => {
            // prefix[0] is the wrapper program; the rest are its args, then the real program.
            let mut cmd = Command::new(&prefix[0]);
            cmd.args(&prefix[1..]);
            cmd.arg(prog);
            cmd.args(args);
            cmd
        }
        None => {
            let mut cmd = Command::new(prog);
            cmd.args(args);
            cmd
        }
    }
}

fn run(prog: &Path, args: &[OsString], sched: SchedClass, nice: i32, what: &str) -> Result<()> {
    let output = build_command(prog, args, sched, nice)
        .output()
        .with_context(|| format!("failed to spawn nydus-image for {what}"))?;
    if !output.status.success() {
        bail!(
            "nydus-image {what} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Deterministic, content-derived subdirectory name for one layer's per-invocation
/// `targz-ref` output dir. Combining the layer's position (readable device-table
/// ordering when debugging) with its blob id (content hash of the *input*, not the
/// nydus-image-chosen output name) means retries of the same job after a crash land
/// in the same place instead of minting a fresh name every attempt -- which matters
/// for the recon sweep and for correlating a stuck job with a directory by eye.
fn layer_invocation_dir(index: usize, blob_id: &str) -> String {
    format!("l{index}-{blob_id}")
}

/// (Re)create `dir` as empty, discarding any stray content a crashed prior
/// invocation may have left behind. Every `nydus-image` invocation below gets its
/// own freshly-wiped directory so "exactly one output file" is a structural
/// guarantee -- nothing else can have written into `dir` since it was last emptied
/// -- rather than something detected heuristically via a before/after diff or an
/// "ignore the known bootstrap name" scan.
fn fresh_dir(dir: &Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("clearing stale dir {}", dir.display())),
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating dir {}", dir.display()))
}

/// Return the at-most-one file in `dir` other than `exclude` (if given). The caller
/// must have just wiped-and-recreated `dir` exclusively for one `nydus-image`
/// invocation (see `fresh_dir`), so finding more than one candidate here means
/// `nydus-image` itself produced unexpected output -- a real bug to surface, not a
/// discovery race to paper over. Zero candidates is a legal outcome for steps where
/// the tool may legitimately emit nothing (a data-less layer produces no zran blob).
fn expect_at_most_one_output(dir: &Path, exclude: Option<&Path>) -> Result<Option<PathBuf>> {
    let exclude_name = exclude.and_then(Path::file_name);
    let mut found = None;
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("reading output dir {}", dir.display()))?
    {
        let entry = entry?;
        if !entry.path().is_file() || Some(entry.file_name().as_os_str()) == exclude_name {
            continue;
        }
        if found.is_some() {
            bail!(
                "nydus-image wrote more than one output file into the fresh dir {} \
                 (dir is private to this invocation, so this is unexpected)",
                dir.display()
            );
        }
        found = Some(entry.path());
    }
    Ok(found)
}

/// Like [`expect_at_most_one_output`], for steps where an output file is mandatory.
fn expect_single_output(dir: &Path, exclude: Option<&Path>) -> Result<PathBuf> {
    expect_at_most_one_output(dir, exclude)?
        .ok_or_else(|| anyhow::anyhow!("nydus-image produced no output file in {}", dir.display()))
}

/// Convert the gzip layers (lower→upper) of a standard OCI image into a
/// node-local RAFS v6 + zran artifact. No registry interaction; the gzip
/// layers are referenced in place.
///
/// `prefetch_files` is an optional ordered list of in-image paths captured by
/// the access tracer during pod startup; when non-empty, the merge step is
/// followed by `nydus-image optimize --prefetch-files`, which bakes the hints
/// into a new bootstrap (replacing the merged one) and writes a packed prefetch
/// blob into `backend_dir`. The fanotify daemon uses the prefetch blob to
/// warm-cache the listed chunks on first access. When `prefetch_files` is
/// empty the optimize step is skipped and `prefetch_blob_id` is `None`.
pub fn convert(
    config: &LocalAccelConfig,
    layers: &[GzipLayer],
    prefetch_files: &[String],
) -> Result<NodeLocalArtifact> {
    if layers.is_empty() {
        bail!("node-local conversion requires at least one layer");
    }
    let stage = &config.work_dir;
    let backend = stage.join("backend");
    let convert_root = stage.join("convert");
    std::fs::create_dir_all(&backend)
        .with_context(|| format!("creating backend dir {}", backend.display()))?;
    std::fs::create_dir_all(&convert_root)?;

    let mut layer_bootstraps = Vec::with_capacity(layers.len());
    let mut blob_ids = Vec::with_capacity(layers.len());
    let mut zran_index_blob_ids = Vec::with_capacity(layers.len());

    for (i, layer) in layers.iter().enumerate() {
        if !layer.path.is_file() {
            bail!(
                "layer {} not found at {}",
                layer.digest,
                layer.path.display()
            );
        }
        let out_dir = convert_root.join(layer_invocation_dir(i, layer.blob_id()));
        fresh_dir(&out_dir)?;
        let bootstrap = out_dir.join("bootstrap");
        let args = targz_ref_args(&layer.path, &bootstrap, &out_dir);
        run(
            &config.nydus_image,
            &args,
            config.sched,
            config.nice,
            "targz-ref convert",
        )?;
        let index = expect_at_most_one_output(&out_dir, Some(&bootstrap))
            .context("locating zran index blob")?;

        let blob_id = layer.blob_id().to_string();
        match index {
            Some(index) => {
                // Stage the backend: symlink the gzip layer in place (no copy), and move the
                // small zran index blob in, both keyed by their nydus blob ids.
                symlink_force(&layer.path, &backend.join(&blob_id))?;
                let index_name = index
                    .file_name()
                    .context("zran index blob has no file name")?
                    .to_string_lossy()
                    .into_owned();
                stage_blob(&index, &backend.join(&index_name), "zran index blob")?;
                zran_index_blob_ids.push(Some(index_name));
            }
            None => {
                // A tar with no regular-file data (directories, whiteouts, metadata-only
                // layers) yields a bootstrap that references no blob, so there is no zran
                // index to stage and the merged blob table will never ask for this layer.
                // The blob id still occupies its position in `blob_ids`: `nydus-image merge
                // --original-blob-ids` requires one id per bootstrap source and ignores the
                // ids of blob-less sources.
                tracing::info!(
                    layer = %layer.digest,
                    "layer has no data chunks; merging namespace only (no zran index blob)"
                );
                zran_index_blob_ids.push(None);
            }
        }

        layer_bootstraps.push(bootstrap);
        blob_ids.push(blob_id);
    }

    let bootstrap = stage.join("bootstrap");
    let margs = merge_args(&bootstrap, &blob_ids, &layer_bootstraps);
    run(
        &config.nydus_image,
        &margs,
        config.sched,
        config.nice,
        "merge",
    )?;

    let prefetch_blob_id = if prefetch_files.is_empty() {
        None
    } else {
        Some(run_optimize(config, &backend, &bootstrap, prefetch_files)?)
    };

    Ok(NodeLocalArtifact {
        bootstrap,
        backend_dir: backend,
        work_dir: stage.clone(),
        layer_blob_ids: blob_ids,
        zran_index_blob_ids,
        prefetch_blob_id,
    })
}

/// Run ONLY the `nydus-image optimize` step against an artifact produced by an
/// earlier [`convert`] call (with empty `prefetch_files`) whose `work_dir` is
/// still on disk. This is the stage-2 half of the two-stage auto-accel
/// pipeline: it reuses the merged bootstrap and the staged backend blobs in
/// `artifact.work_dir`, so create/merge are NOT re-run. The merged bootstrap is
/// replaced in place with the optimized one and a packed prefetch blob is added
/// to the backend; the returned artifact is the input with `prefetch_blob_id`
/// set.
///
/// `config.work_dir` MUST equal `artifact.work_dir` (the optimize step stages
/// its scratch — `prefetch.json`, `optimize-out/`, `bootstrap.optimized` —
/// under `config.work_dir`).
pub fn optimize_existing(
    config: &LocalAccelConfig,
    artifact: &NodeLocalArtifact,
    prefetch_files: &[String],
) -> Result<NodeLocalArtifact> {
    if prefetch_files.is_empty() {
        bail!("optimize_existing requires a non-empty prefetch file list");
    }
    if !artifact.bootstrap.is_file() {
        bail!(
            "merged bootstrap missing at {}; cannot optimize in place",
            artifact.bootstrap.display()
        );
    }
    if !artifact.backend_dir.is_dir() {
        bail!(
            "backend dir missing at {}; cannot optimize in place",
            artifact.backend_dir.display()
        );
    }
    let prefetch_blob_id = run_optimize(
        config,
        &artifact.backend_dir,
        &artifact.bootstrap,
        prefetch_files,
    )?;
    Ok(NodeLocalArtifact {
        prefetch_blob_id: Some(prefetch_blob_id),
        ..artifact.clone()
    })
}

/// Bake prefetch hints into the merged bootstrap via `nydus-image optimize`.
/// Returns the id (= file name in `backend_dir`) of the new prefetch blob.
///
/// `nydus-image optimize --prefetch-files` expects a v1 JSON file (see
/// `builder/src/optimize_prefetch.rs::PrefetchJson`); plain newline lists are
/// rejected. `--blob-dir` (read-only: existing blobs the bootstrap references) and
/// `--output-blob-dir` (write-only: the new prefetch blob) are independent
/// directories in the `nydus-image` CLI, so the new blob is written into its own
/// fresh, otherwise-empty dir instead of `backend` -- turning "find the new file"
/// into a direct scan of a dir nothing else could have touched, then a single
/// deterministic move into `backend`.
fn run_optimize(
    config: &LocalAccelConfig,
    backend: &Path,
    merged_bootstrap: &Path,
    prefetch_files: &[String],
) -> Result<String> {
    let stage = config.work_dir.as_path();
    let prefetch_json_path = stage.join("prefetch.json");
    let prefetch_json = serde_json::json!({
        "version": "v1",
        "files": prefetch_files.iter().map(|p| {
            serde_json::json!({ "path": p, "ranges": null })
        }).collect::<Vec<_>>(),
    });
    std::fs::write(&prefetch_json_path, serde_json::to_vec(&prefetch_json)?)
        .with_context(|| format!("writing {}", prefetch_json_path.display()))?;

    let optimize_out_dir = stage.join("optimize-out");
    fresh_dir(&optimize_out_dir)?;

    let optimized_bootstrap = stage.join("bootstrap.optimized");
    let args: Vec<OsString> = vec![
        "optimize".into(),
        "--bootstrap".into(),
        merged_bootstrap.into(),
        "--prefetch-files".into(),
        prefetch_json_path.as_path().into(),
        "--blob-dir".into(),
        backend.into(),
        "--output-bootstrap".into(),
        optimized_bootstrap.as_path().into(),
        "--output-blob-dir".into(),
        optimize_out_dir.as_path().into(),
    ];
    run(
        &config.nydus_image,
        &args,
        config.sched,
        config.nice,
        "optimize",
    )?;

    std::fs::rename(&optimized_bootstrap, merged_bootstrap)
        .with_context(|| "replacing merged bootstrap with optimized one")?;

    let new_blob = expect_single_output(&optimize_out_dir, None)
        .context("locating optimize's new prefetch blob")?;
    let blob_name = new_blob
        .file_name()
        .context("prefetch blob has no file name")?
        .to_string_lossy()
        .into_owned();
    stage_blob(&new_blob, &backend.join(&blob_name), "prefetch blob")?;

    Ok(blob_name)
}

/// Move `src` into the backend as `dst`, both of which live under the same
/// per-image `work_dir` (so a plain rename normally succeeds). Falls back to a
/// copy+remove ONLY on `EXDEV` (rename across filesystems), so a genuine rename
/// failure -- `EACCES`, `ENOSPC`, a vanished source -- surfaces as itself instead
/// of being masked by whatever the copy attempt then reports.
fn stage_blob(src: &Path, dst: &Path, what: &str) -> Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            std::fs::copy(src, dst)
                .with_context(|| format!("copying {} across filesystems into backend", what))?;
            let _ = std::fs::remove_file(src);
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("staging {} into backend", what)),
    }
}

fn symlink_force(target: &Path, link: &Path) -> Result<()> {
    let _ = std::fs::remove_file(link);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
            .with_context(|| format!("symlinking {} -> {}", link.display(), target.display()))
    }
    #[cfg(not(unix))]
    {
        std::fs::copy(target, link)
            .map(|_| ())
            .with_context(|| format!("copying {} -> {}", target.display(), link.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn blob_id_strips_algorithm_prefix() {
        let l = GzipLayer {
            digest: "sha256:deadbeef".into(),
            path: "/x".into(),
        };
        assert_eq!(l.blob_id(), "deadbeef");
        let l2 = GzipLayer {
            digest: "cafef00d".into(),
            path: "/x".into(),
        };
        assert_eq!(l2.blob_id(), "cafef00d");
    }

    #[test]
    fn sched_prefix_is_os_specific() {
        assert_eq!(SchedClass::Normal.command_prefix(10, "linux"), None);
        assert_eq!(
            SchedClass::Idle.command_prefix(10, "linux"),
            Some(
                ["ionice", "-c", "3", "nice", "-n", "10"]
                    .iter()
                    .map(OsString::from)
                    .collect()
            )
        );
        assert_eq!(
            SchedClass::Idle.command_prefix(10, "macos"),
            Some(
                ["taskpolicy", "-c", "utility"]
                    .iter()
                    .map(OsString::from)
                    .collect()
            )
        );
        // nice is clamped into [0,19].
        let linux = SchedClass::Idle.command_prefix(99, "linux").unwrap();
        assert_eq!(linux.last().unwrap(), OsStr::new("19"));
        // Unknown OS: no wrapper.
        assert_eq!(SchedClass::Idle.command_prefix(10, "plan9"), None);
    }

    #[test]
    fn targz_ref_args_are_well_formed() {
        let args = targz_ref_args(
            Path::new("/cs/layer.tar.gz"),
            Path::new("/w/l0/bootstrap"),
            Path::new("/w/l0"),
        );
        let s: Vec<String> = args.iter().map(|a| a.to_string_lossy().into()).collect();
        assert_eq!(s[0], "create");
        assert!(s.windows(2).any(|w| w == ["--type", "targz-ref"]));
        assert!(s.windows(2).any(|w| w == ["--fs-version", "6"]));
        assert!(s.windows(2).any(|w| w == ["-B", "/w/l0/bootstrap"]));
        assert_eq!(s.last().unwrap(), "/cs/layer.tar.gz");
    }

    #[test]
    fn merge_args_join_blob_ids_in_order() {
        let args = merge_args(
            Path::new("/w/bootstrap"),
            &["d0".into(), "d1".into()],
            &[
                PathBuf::from("/w/l0/bootstrap"),
                PathBuf::from("/w/l1/bootstrap"),
            ],
        );
        let s: Vec<String> = args.iter().map(|a| a.to_string_lossy().into()).collect();
        assert_eq!(s[0], "merge");
        assert!(s.windows(2).any(|w| w == ["--original-blob-ids", "d0,d1"]));
        // sources follow, lower then upper
        assert_eq!(s[s.len() - 2], "/w/l0/bootstrap");
        assert_eq!(s[s.len() - 1], "/w/l1/bootstrap");
    }

    #[test]
    fn layer_invocation_dir_is_deterministic_and_disambiguates_duplicate_digests() {
        // Same (index, blob_id) always yields the same name -- this is what lets a
        // retry of the same job reuse (and re-wipe) the same location.
        assert_eq!(layer_invocation_dir(0, "deadbeef"), "l0-deadbeef");
        assert_eq!(layer_invocation_dir(0, "deadbeef"), "l0-deadbeef");
        // Different positions with the same content digest (a degenerate but legal
        // OCI image with two identical layers) must not collide.
        assert_ne!(
            layer_invocation_dir(0, "deadbeef"),
            layer_invocation_dir(1, "deadbeef")
        );
    }

    #[test]
    fn fresh_dir_wipes_stray_files_left_by_a_crashed_prior_invocation() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("l0-abc123");
        std::fs::create_dir_all(&target).unwrap();
        // Simulate debris from a crashed earlier attempt: an old bootstrap AND an
        // extra stray file that would trip `expect_single_output` if it were not
        // wiped before the next invocation.
        std::fs::write(target.join("bootstrap"), b"old").unwrap();
        std::fs::write(target.join("stray-leftover"), b"old").unwrap();

        fresh_dir(&target).unwrap();

        let entries: Vec<_> = std::fs::read_dir(&target).unwrap().collect();
        assert!(entries.is_empty(), "fresh_dir must leave the dir empty");
    }

    #[test]
    fn fresh_dir_creates_a_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("does/not/exist/yet");
        fresh_dir(&target).unwrap();
        assert!(target.is_dir());
    }

    #[test]
    fn expect_single_output_finds_the_one_non_excluded_file() {
        let tmp = tempfile::tempdir().unwrap();
        let bootstrap = tmp.path().join("bootstrap");
        std::fs::write(&bootstrap, b"boot").unwrap();
        let index = tmp.path().join("a1b2c3");
        std::fs::write(&index, b"index").unwrap();

        let found = expect_single_output(tmp.path(), Some(&bootstrap)).unwrap();
        assert_eq!(found, index);
    }

    #[test]
    fn expect_single_output_errors_on_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let err = expect_single_output(tmp.path(), None).unwrap_err();
        assert!(err.to_string().contains("no output file"));
    }

    #[test]
    fn expect_at_most_one_output_returns_none_for_an_empty_dir() {
        // A data-less layer (directory/whiteout-only tar) legitimately produces a
        // bootstrap and nothing else; the convert loop maps that to a None index.
        let tmp = tempfile::tempdir().unwrap();
        let bootstrap = tmp.path().join("bootstrap");
        std::fs::write(&bootstrap, b"boot").unwrap();
        let found = expect_at_most_one_output(tmp.path(), Some(&bootstrap)).unwrap();
        assert_eq!(found, None);
    }

    #[test]
    fn stage_blob_moves_within_the_same_dir_and_surfaces_a_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("new-blob");
        std::fs::write(&src, b"payload").unwrap();
        let dst = tmp.path().join("staged");

        stage_blob(&src, &dst, "test blob").unwrap();
        assert!(!src.exists(), "source should be consumed by the move");
        assert_eq!(std::fs::read(&dst).unwrap(), b"payload");

        // A genuine rename failure (source gone) surfaces as an error, not a mask.
        let err = stage_blob(&tmp.path().join("absent"), &dst, "test blob").unwrap_err();
        assert!(err.to_string().contains("staging test blob"));
    }

    #[test]
    fn expect_single_output_errors_when_more_than_one_candidate_remains() {
        // With a fresh, private dir this can only happen if nydus-image itself wrote
        // more than one file -- a real bug, which is why this stays an error rather
        // than a silent pick.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("blob-a"), b"a").unwrap();
        std::fs::write(tmp.path().join("blob-b"), b"b").unwrap();
        let err = expect_single_output(tmp.path(), None).unwrap_err();
        assert!(err.to_string().contains("more than one"));
    }
}
