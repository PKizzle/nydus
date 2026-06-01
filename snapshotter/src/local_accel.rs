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
//! The resulting `(bootstrap, backend_dir, work_dir)` feeds a fanotify `BlobCacheEntry`; the
//! `FanotifyHandler` self-stages the EROFS device files and serves reads on demand.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

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
/// request maps to the right primitive (this addresses the previously Linux-only `ionice` path).
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

/// Result of a node-local conversion, ready to feed a fanotify `BlobCacheEntry`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeLocalArtifact {
    /// Merged RAFS v6 bootstrap (the fanotify staging dir's `bootstrap`).
    pub bootstrap: PathBuf,
    /// `localfs` backend directory holding the gzip layers (by digest) and zran index blobs.
    pub backend_dir: PathBuf,
    /// Blob-cache working directory (also the fanotify staging dir); equals the parent of
    /// `bootstrap`.
    pub work_dir: PathBuf,
    /// Original gzip-layer blob ids, lower→upper, in device-table order.
    pub layer_blob_ids: Vec<String>,
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

/// The single non-bootstrap file produced by a per-layer `targz-ref` conversion is its zran index
/// blob; find it in `blob_out_dir`.
fn find_zran_index(blob_out_dir: &Path, bootstrap: &Path) -> Result<PathBuf> {
    let boot_name = bootstrap.file_name();
    let mut found = None;
    for entry in std::fs::read_dir(blob_out_dir)
        .with_context(|| format!("reading conversion output dir {}", blob_out_dir.display()))?
    {
        let entry = entry?;
        if entry.path().is_file() && Some(entry.file_name().as_os_str()) != boot_name {
            if found.is_some() {
                bail!(
                    "expected exactly one zran index blob in {}, found multiple",
                    blob_out_dir.display()
                );
            }
            found = Some(entry.path());
        }
    }
    found
        .ok_or_else(|| anyhow::anyhow!("no zran index blob produced in {}", blob_out_dir.display()))
}

/// Convert the gzip layers (lower→upper) of a standard OCI image into a node-local RAFS v6 + zran
/// artifact. No registry interaction; the gzip layers are referenced in place.
pub fn convert(config: &LocalAccelConfig, layers: &[GzipLayer]) -> Result<NodeLocalArtifact> {
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

    for (i, layer) in layers.iter().enumerate() {
        if !layer.path.is_file() {
            bail!(
                "layer {} not found at {}",
                layer.digest,
                layer.path.display()
            );
        }
        let out_dir = convert_root.join(format!("l{i}"));
        std::fs::create_dir_all(&out_dir)?;
        let bootstrap = out_dir.join("bootstrap");
        let args = targz_ref_args(&layer.path, &bootstrap, &out_dir);
        run(
            &config.nydus_image,
            &args,
            config.sched,
            config.nice,
            "targz-ref convert",
        )?;
        let index = find_zran_index(&out_dir, &bootstrap)?;

        // Stage the backend: symlink the gzip layer in place (no copy), and move the small zran
        // index blob in, both keyed by their nydus blob ids.
        let blob_id = layer.blob_id().to_string();
        symlink_force(&layer.path, &backend.join(&blob_id))?;
        let index_name = index
            .file_name()
            .context("zran index blob has no file name")?;
        std::fs::rename(&index, backend.join(index_name))
            .or_else(|_| std::fs::copy(&index, backend.join(index_name)).map(|_| ()))
            .with_context(|| "staging zran index blob into backend")?;

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

    Ok(NodeLocalArtifact {
        bootstrap,
        backend_dir: backend,
        work_dir: stage.clone(),
        layer_blob_ids: blob_ids,
    })
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

#[allow(dead_code)]
fn os_str(s: &str) -> &OsStr {
    OsStr::new(s)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
