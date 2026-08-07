// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Find out what a running container is made of, for `nydusify commit`.
//!
//! Commit needs three things from containerd: which image the container was
//! started from, and where its overlay `upperdir` and `lowerdir`s live. All
//! three come out of containerd's own CLI:
//!
//! ```text
//! ctr -n <ns> container info <id>            -> .Image, .Snapshotter, .SnapshotKey
//! ctr -n <ns> snapshot --snapshotter <s> mounts <target> <key>
//!                                            -> mount -t overlay ... -o ...,upperdir=…,lowerdir=…
//! ```
//!
//! Shelling out to `ctr` rather than dialling containerd's gRPC API directly is
//! the same convention the rest of nydusify uses for `nydus-image`/`nydusd`, and
//! it keeps the tonic/tokio client stack — which the snapshotter has to
//! quarantine behind its own runtime (see `snapshotter/src/content_store.rs`) —
//! out of a compio binary entirely. `ctr` ships with containerd, so it is
//! present wherever a container is running.
//!
//! Everything that parses `ctr` output lives in free functions below so it can
//! be tested without a containerd.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tracing::{debug, warn};

/// The label nerdctl stores a container's `--name` under, so `--container` can
/// take the name a user actually typed.
const NERDCTL_NAME_LABEL: &str = "nerdctl/name";

/// How to invoke containerd's CLI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerdCli {
    /// Path to `ctr` (or a drop-in).
    pub binary: PathBuf,
    /// containerd namespace holding the container (nerdctl's default is
    /// `default`, Kubernetes uses `k8s.io`).
    pub namespace: String,
    /// containerd's gRPC socket, when it is not at the default path.
    pub address: Option<PathBuf>,
}

/// What commit needs to know about the container being snapshotted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inspected {
    /// The resolved containerd container ID.
    pub id: String,
    /// The image reference the container was created from.
    pub image: String,
    /// The snapshotter that owns the container's snapshot.
    pub snapshotter: String,
    /// The container's active snapshot key.
    pub snapshot_key: String,
    /// The overlay read-write layer — the thing commit turns into a layer.
    pub upper_dir: PathBuf,
    /// The overlay read-only layers, upper-most first (overlay's own order).
    pub lower_dirs: Vec<PathBuf>,
}

/// The subset of `ctr container info` output commit reads. containerd marshals
/// its `containers.Container` struct with Go field names; the aliases accept the
/// snake_case spelling too so a differently-marshalled build still parses.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct ContainerInfo {
    #[serde(rename = "ID", alias = "id", default)]
    pub id: String,
    #[serde(rename = "Image", alias = "image", default)]
    pub image: String,
    #[serde(rename = "Snapshotter", alias = "snapshotter", default)]
    pub snapshotter: String,
    #[serde(rename = "SnapshotKey", alias = "snapshot_key", default)]
    pub snapshot_key: String,
    #[serde(rename = "Labels", alias = "labels", default)]
    pub labels: std::collections::BTreeMap<String, String>,
}

impl ContainerdCli {
    /// Resolve `container` — an ID, an unambiguous ID prefix, or a nerdctl
    /// `--name` — and read everything commit needs about it.
    pub fn inspect(&self, container: &str) -> Result<Inspected> {
        let info = self.container_info(container)?;
        if info.image.is_empty() {
            bail!(
                "container {} has no image recorded in containerd; commit needs the \
                 image it was created from",
                info.id
            );
        }
        if info.snapshot_key.is_empty() {
            bail!(
                "container {} has no snapshot key; it has no writable layer to commit",
                info.id
            );
        }

        let snapshotter = if info.snapshotter.is_empty() {
            warn!(
                container = %info.id,
                "containerd reported no snapshotter for this container; assuming \"nydus\""
            );
            "nydus".to_string()
        } else {
            info.snapshotter.clone()
        };

        let mounts = self.snapshot_mounts(&snapshotter, &info.snapshot_key)?;
        let (upper_dir, lower_dirs) = parse_overlay_mount(&mounts).with_context(|| {
            format!(
                "read the overlay layout of snapshot {} from the {snapshotter} snapshotter",
                info.snapshot_key
            )
        })?;

        Ok(Inspected {
            id: info.id,
            image: info.image,
            snapshotter,
            snapshot_key: info.snapshot_key,
            upper_dir,
            lower_dirs,
        })
    }

    /// `ctr container info`, retried against an ID prefix or a nerdctl name when
    /// the exact ID misses.
    fn container_info(&self, container: &str) -> Result<ContainerInfo> {
        match self.try_container_info(container) {
            Ok(info) => return Ok(info),
            Err(e) => debug!(%container, error = %e, "no container with that exact id; searching"),
        }
        let id = self.resolve_container_id(container)?;
        self.try_container_info(&id)
            .with_context(|| format!("inspect container {id}"))
    }

    fn try_container_info(&self, id: &str) -> Result<ContainerInfo> {
        let stdout = self.run(&["container", "info", id], "read container info")?;
        parse_container_info(&stdout)
    }

    /// Search the namespace for a container matching `wanted` by ID prefix or by
    /// nerdctl name.
    fn resolve_container_id(&self, wanted: &str) -> Result<String> {
        let listed = self.run(&["containers", "list", "-q"], "list containers")?;
        let ids: Vec<String> = listed
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();

        let by_prefix: Vec<&String> = ids.iter().filter(|id| id.starts_with(wanted)).collect();
        match by_prefix.as_slice() {
            [only] => return Ok((*only).clone()),
            [] => {}
            many => bail!(
                "container id prefix {wanted:?} is ambiguous in namespace {}: it matches {} \
                 containers ({}). Pass the full id.",
                self.namespace,
                many.len(),
                many.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        }

        // Not an id at all — try it as a nerdctl container name.
        let mut named: Vec<String> = Vec::new();
        for id in &ids {
            if let Ok(info) = self.try_container_info(id)
                && info.labels.get(NERDCTL_NAME_LABEL).map(String::as_str) == Some(wanted)
            {
                named.push(id.clone());
            }
        }
        match named.as_slice() {
            [only] => Ok(only.clone()),
            [] => bail!(
                "no container {wanted:?} in containerd namespace {} ({} container(s) there). \
                 Pass a container id, an unambiguous id prefix, or a nerdctl --name, and \
                 --containerd-namespace if it lives in another namespace.",
                self.namespace,
                ids.len(),
            ),
            many => bail!(
                "container name {wanted:?} is ambiguous in namespace {}: {} containers carry it",
                self.namespace,
                many.len(),
            ),
        }
    }

    /// The pid of the container's running task, for entering its mount
    /// namespace (`commit --with-path`).
    ///
    /// Only needed for `--with-path`, so it is a separate call rather than part
    /// of [`inspect`](Self::inspect): a container whose task has exited still
    /// has a writable layer worth committing, and failing the whole commit for
    /// want of a pid nobody asked about would be wrong.
    pub fn task_pid(&self, container_id: &str) -> Result<u32> {
        let listed = self.run(&["task", "ls"], "list tasks")?;
        parse_task_pid(&listed, container_id)
    }

    /// `ctr snapshot --snapshotter <s> mounts <target> <key>`. The target path is
    /// only echoed back into the printed mount command — nothing is mounted.
    fn snapshot_mounts(&self, snapshotter: &str, key: &str) -> Result<String> {
        self.run(
            &[
                "snapshot",
                "--snapshotter",
                snapshotter,
                "mounts",
                "/nydusify-commit-unused-mount-target",
                key,
            ],
            "read snapshot mounts",
        )
    }

    fn run(&self, args: &[&str], what: &str) -> Result<String> {
        let mut command = Command::new(&self.binary);
        command.arg("--namespace").arg(&self.namespace);
        if let Some(address) = &self.address {
            command.arg("--address").arg(address);
        }
        command.args(args);
        debug!(?command, "running containerd cli");

        let output = command.output().with_context(|| {
            format!(
                "spawn `{}` to {what} (install containerd's ctr, or point --containerd-cli at it)",
                self.binary.display()
            )
        })?;
        if !output.status.success() {
            bail!(
                "`{} {}` failed ({}): {}",
                self.binary.display(),
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
            );
        }
        String::from_utf8(output.stdout)
            .with_context(|| format!("`{}` printed non-UTF-8 output", self.binary.display()))
    }
}

/// Parse `ctr container info` JSON.
pub fn parse_container_info(stdout: &str) -> Result<ContainerInfo> {
    let info: ContainerInfo =
        serde_json::from_str(stdout).context("parse `ctr container info` JSON")?;
    if info.id.is_empty() {
        bail!("`ctr container info` returned no container id");
    }
    Ok(info)
}

/// Pull `upperdir` and `lowerdir` out of a printed `ctr snapshot mounts` command.
///
/// The output is a shell command, e.g.
/// `mount -t overlay overlay -o index=off,workdir=…,upperdir=…,lowerdir=A:B /target`,
/// possibly one line per mount.
pub fn parse_overlay_mount(stdout: &str) -> Result<(PathBuf, Vec<PathBuf>)> {
    for line in stdout.lines() {
        let Some(options) = mount_options(line) else {
            continue;
        };
        let mut upper = None;
        let mut lower = None;
        for option in options.split(',') {
            if let Some(value) = option.strip_prefix("upperdir=") {
                upper = Some(value);
            } else if let Some(value) = option.strip_prefix("lowerdir=") {
                lower = Some(value);
            }
        }
        let Some(upper) = upper else {
            continue;
        };
        // A container whose image has a single layer legitimately has no
        // lowerdir at all, so its absence is not an error.
        let lower_dirs = lower
            .into_iter()
            .flat_map(|l| l.split(':'))
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .collect();
        return Ok((PathBuf::from(upper), lower_dirs));
    }
    bail!(
        "no overlay mount with an upperdir in the snapshotter's output. A container \
         committed this way must be running on an overlay snapshot with a writable \
         layer.\n{}",
        stdout.trim(),
    )
}

/// The `-o` option string of a printed mount command, if it has one.
fn mount_options(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "-o" {
            return tokens.next();
        }
        if let Some(rest) = token.strip_prefix("-o") {
            // `-oindex=off,…` — no space after the flag.
            if !rest.is_empty() {
                return Some(rest);
            }
        }
    }
    // Some containerd builds print the option list bare. Fall back to any token
    // that carries an overlay directory.
    line.split_whitespace()
        .find(|t| t.contains("upperdir=") || t.contains("lowerdir="))
}

/// Pull the pid of `container_id`'s task out of `ctr task ls`.
///
/// The output is a header plus one `TASK PID STATUS` row per task:
///
/// ```text
/// TASK                PID      STATUS
/// 0d1c9f1a...         31337    RUNNING
/// ```
///
/// A task in any state other than `RUNNING` has no process to enter, so it is
/// rejected here rather than surfacing as an opaque `nsenter` failure.
pub fn parse_task_pid(stdout: &str, container_id: &str) -> Result<u32> {
    let mut seen = 0usize;
    for line in stdout.lines() {
        let mut fields = line.split_whitespace();
        let (Some(task), Some(pid), status) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        if task == "TASK" {
            continue;
        }
        seen += 1;
        if task != container_id {
            continue;
        }
        let pid: u32 = pid
            .parse()
            .with_context(|| format!("`ctr task ls` reported a non-numeric pid {pid:?}"))?;
        match status {
            Some("RUNNING") => return Ok(pid),
            Some(other) => bail!(
                "container {container_id} is {other}, not RUNNING; --with-path has to enter \
                 the container's mount namespace, which needs a live process"
            ),
            None => bail!("`ctr task ls` row for {container_id} has no status column"),
        }
    }
    bail!(
        "container {container_id} has no task ({seen} task(s) in this namespace). --with-path \
         commits paths from inside the running container, so it needs one; drop --with-path to \
         commit only the writable layer."
    )
}

/// Whether `path` looks like a directory we can read — used to turn a stale
/// snapshot record into an actionable error before the walk starts.
pub fn require_directory(path: &Path, what: &str) -> Result<()> {
    let md = std::fs::metadata(path)
        .with_context(|| format!("stat the container's {what} at {}", path.display()))?;
    if !md.is_dir() {
        bail!(
            "the container's {what} at {} is not a directory",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTR_MOUNTS: &str = "mount -t overlay overlay -o index=off,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/42/work,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/42/fs,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/41/fs:/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/40/fs /nydusify-commit-unused-mount-target";

    #[test]
    fn parses_the_overlay_layout_ctr_prints() {
        let (upper, lower) = parse_overlay_mount(CTR_MOUNTS).unwrap();

        assert_eq!(
            upper,
            PathBuf::from("/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/42/fs"),
        );
        assert_eq!(
            lower,
            vec![
                PathBuf::from(
                    "/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/41/fs"
                ),
                PathBuf::from(
                    "/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/40/fs"
                ),
            ],
        );
    }

    #[test]
    fn accepts_a_single_layer_image_with_no_lowerdir() {
        let (upper, lower) = parse_overlay_mount(
            "mount -t overlay overlay -o upperdir=/snap/1/fs,workdir=/snap/1/work /t",
        )
        .unwrap();

        assert_eq!(upper, PathBuf::from("/snap/1/fs"));
        assert!(lower.is_empty());
    }

    /// The Go committer indexed `mount[0]` straight after fetching the snapshot
    /// mounts and panicked when containerd returned none (upstream 1ba59b8d).
    /// This port cannot: it scans printed lines, so "no mounts" is just an empty
    /// input that has to produce the same diagnostic as unusable output.
    #[test]
    fn no_mounts_at_all_is_an_error_not_a_panic() {
        for stdout in ["", "\n", "   \n\t\n"] {
            let err = parse_overlay_mount(stdout).unwrap_err();
            assert!(
                err.to_string().contains("no overlay mount"),
                "unexpected for {stdout:?}: {err}"
            );
        }
    }

    #[test]
    fn accepts_the_flag_and_value_written_together() {
        let (upper, _) =
            parse_overlay_mount("mount -t overlay overlay -oindex=off,upperdir=/snap/9/fs /t")
                .unwrap();

        assert_eq!(upper, PathBuf::from("/snap/9/fs"));
    }

    #[test]
    fn a_read_only_snapshot_is_rejected_with_the_snapshotter_output() {
        // What `ctr snapshot mounts` prints for a committed (view) snapshot:
        // read-only overlay, no upperdir to commit.
        let err = parse_overlay_mount(
            "mount -t overlay overlay -o index=off,lowerdir=/snap/3/fs:/snap/2/fs /t",
        )
        .unwrap_err();

        assert!(err.to_string().contains("upperdir"), "unexpected: {err}");
        assert!(err.to_string().contains("/snap/3/fs"), "unexpected: {err}");
    }

    #[test]
    fn a_bind_mounted_snapshot_is_rejected() {
        let err =
            parse_overlay_mount("mount -t bind /var/lib/containerd/snapshots/7/fs /t -o rbind,rw")
                .unwrap_err();

        assert!(err.to_string().contains("overlay"), "unexpected: {err}");
    }

    #[test]
    fn skips_leading_lines_that_carry_no_overlay_options() {
        let stdout = format!("some containerd banner\n{CTR_MOUNTS}\n");

        let (upper, _) = parse_overlay_mount(&stdout).unwrap();

        assert!(upper.ends_with("42/fs"));
    }

    #[test]
    fn parses_container_info_with_go_field_names() {
        let info = parse_container_info(
            r#"{
                "ID": "0d1c9f1a",
                "Labels": {"nerdctl/name": "web"},
                "Image": "ghcr.io/example/app:latest-nydus",
                "SnapshotKey": "sha256:abc",
                "Snapshotter": "nydus",
                "Spec": {"ociVersion": "1.0.2"}
            }"#,
        )
        .unwrap();

        assert_eq!(info.id, "0d1c9f1a");
        assert_eq!(info.image, "ghcr.io/example/app:latest-nydus");
        assert_eq!(info.snapshotter, "nydus");
        assert_eq!(info.snapshot_key, "sha256:abc");
        assert_eq!(info.labels.get(NERDCTL_NAME_LABEL).unwrap(), "web");
    }

    #[test]
    fn parses_container_info_with_snake_case_field_names() {
        let info =
            parse_container_info(r#"{"id": "abc", "image": "x:1", "snapshot_key": "k"}"#).unwrap();

        assert_eq!(info.id, "abc");
        assert_eq!(info.snapshot_key, "k");
        assert!(info.snapshotter.is_empty());
    }

    const CTR_TASKS: &str = "TASK                                                                PID       STATUS\n\
        0d1c9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e    31337     RUNNING\n\
        aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66    404       STOPPED\n";

    #[test]
    fn finds_the_pid_of_a_running_task() {
        let pid = parse_task_pid(
            CTR_TASKS,
            "0d1c9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e",
        )
        .unwrap();

        assert_eq!(pid, 31337);
    }

    #[test]
    fn refuses_a_task_that_is_not_running() {
        let err = parse_task_pid(
            CTR_TASKS,
            "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66",
        )
        .unwrap_err();

        assert!(err.to_string().contains("STOPPED"), "unexpected: {err}");
        assert!(err.to_string().contains("--with-path"), "unexpected: {err}");
    }

    #[test]
    fn reports_a_container_with_no_task_at_all() {
        let err = parse_task_pid(CTR_TASKS, "deadbeef").unwrap_err();

        assert!(err.to_string().contains("has no task"), "unexpected: {err}");
        // The count excludes the header row.
        assert!(err.to_string().contains("2 task(s)"), "unexpected: {err}");
    }

    #[test]
    fn rejects_container_info_without_an_id() {
        let err = parse_container_info(r#"{"Image": "x:1"}"#).unwrap_err();

        assert!(
            err.to_string().contains("no container id"),
            "unexpected: {err}"
        );
    }
}
