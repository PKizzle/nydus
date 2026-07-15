// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Containerd mount-spec helpers for bind and overlay mounts.

use anyhow::{Result, bail};
use containerd_snapshots::api::types::Mount;
use std::path::{Path, PathBuf};
use tracing::warn;

/// `mount(2)` copies the option string into a single page, and containerd
/// budgets `pagesize - 512` bytes for the `lowerdir=` option (512 reserved
/// for `upperdir=`/`workdir=`/flags). Assume 4K pages: a 16K/64K-page host
/// only gets more headroom.
const LOWERDIR_OPTION_BUDGET: usize = 4096 - 512;

pub(super) fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(":")
}

/// Pre-flight a deep lowerdir chain against the kernel's one-page mount
/// option limit before handing containerd a mount spec that can only fail
/// with `E2BIG` at `mount(2)` time.
///
/// The snapshotter never mounts overlays itself — it returns a mount spec
/// over gRPC and containerd performs the syscall. When the raw option
/// exceeds its budget, containerd rewrites the lowerdirs relative to their
/// longest common prefix and `chdir`s there for the syscall
/// (`compactLowerdirOption` + `mountAt` in containerd's
/// `core/mount/mount_linux.go`, threshold `pagesize - 512`). All our
/// lowerdirs share `<root>/snapshots/`, so compaction is highly effective;
/// only a chain whose *compacted* form still exceeds the budget must be
/// rejected here.
pub(super) fn ensure_lowerdir_budget(lowerdirs: &[PathBuf]) -> Result<()> {
    let raw_len = "lowerdir=".len() + join_paths(lowerdirs).len();
    if raw_len <= LOWERDIR_OPTION_BUDGET {
        return Ok(());
    }

    let compacted_len = "lowerdir=".len() + compacted_lowerdir_len(lowerdirs);
    if compacted_len > LOWERDIR_OPTION_BUDGET {
        bail!(
            "overlay lowerdir chain of {} layers exceeds the kernel's one-page mount \
             option limit even after containerd's common-prefix compaction \
             ({compacted_len} > {LOWERDIR_OPTION_BUDGET} bytes); this image has too \
             many layers for the plain-overlay fallback",
            lowerdirs.len()
        );
    }
    warn!(
        layers = lowerdirs.len(),
        raw_len,
        compacted_len,
        "overlay lowerdir option exceeds one page uncompacted; relying on containerd's \
         lowerdir compaction (compactLowerdirOption) at mount time"
    );
    Ok(())
}

/// Length of the `lowerdir=` value after containerd's compaction: the paths
/// rewritten relative to their longest common directory prefix, joined by
/// `:`. Pure so the arithmetic is unit-testable.
fn compacted_lowerdir_len(lowerdirs: &[PathBuf]) -> usize {
    let common = common_prefix_components(lowerdirs);
    // containerd refuses to compact against "/" (or "."): a bare RootDir
    // prefix (1 component) buys nothing, so the raw length stands.
    if common <= 1 {
        return join_paths(lowerdirs).len();
    }
    let prefix_components = lowerdirs
        .iter()
        .map(|p| p.components().count().saturating_sub(1))
        .min()
        .unwrap_or(0)
        .min(common);

    let joined: usize = lowerdirs
        .iter()
        .map(|p| {
            p.components()
                .skip(prefix_components)
                .collect::<PathBuf>()
                .as_os_str()
                .len()
        })
        .sum();
    joined + lowerdirs.len().saturating_sub(1)
}

/// Number of leading path components shared by every path in `paths`.
fn common_prefix_components(paths: &[PathBuf]) -> usize {
    let Some(first) = paths.first() else { return 0 };
    let mut shared: Vec<_> = first.components().collect();
    for path in &paths[1..] {
        let matching = shared
            .iter()
            .zip(path.components())
            .take_while(|(a, b)| **a == *b)
            .count();
        shared.truncate(matching);
    }
    shared.len()
}

pub(super) fn bind_mount(source: &Path, readonly: bool) -> Mount {
    let mut options = vec!["rbind".to_string()];
    options.push(if readonly { "ro" } else { "rw" }.to_string());
    Mount {
        r#type: "bind".to_string(),
        source: source.display().to_string(),
        target: String::new(),
        options,
    }
}

pub(super) fn overlay_mount(
    lowerdirs: &[PathBuf],
    upperdir: Option<&Path>,
    workdir: Option<&Path>,
) -> Mount {
    let mut options = vec![format!("lowerdir={}", join_paths(lowerdirs))];
    match (upperdir, workdir) {
        (Some(upper), Some(work)) => {
            options.push(format!("upperdir={}", upper.display()));
            options.push(format!("workdir={}", work.display()));
        }
        _ => options.push("ro".to_string()),
    }

    Mount {
        r#type: "overlay".to_string(),
        source: "overlay".to_string(),
        target: String::new(),
        options,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_mount_sets_readonly_or_readwrite_option() {
        let rw = bind_mount(Path::new("/tmp/rw"), false);
        assert_eq!(rw.r#type, "bind");
        assert!(rw.options.contains(&"rw".to_string()));

        let ro = bind_mount(Path::new("/tmp/ro"), true);
        assert!(ro.options.contains(&"ro".to_string()));
    }

    #[test]
    fn overlay_mount_with_upper_is_writable() {
        let lower = vec![PathBuf::from("/lower")];
        let mount = overlay_mount(&lower, Some(Path::new("/upper")), Some(Path::new("/work")));
        assert!(mount.options.iter().any(|o| o == "lowerdir=/lower"));
        assert!(mount.options.iter().any(|o| o == "upperdir=/upper"));
        assert!(mount.options.iter().any(|o| o == "workdir=/work"));
        assert!(!mount.options.contains(&"ro".to_string()));
    }

    #[test]
    fn overlay_mount_without_upper_is_readonly() {
        let lower = vec![PathBuf::from("/lower")];
        let mount = overlay_mount(&lower, None, None);
        assert!(mount.options.contains(&"ro".to_string()));
    }

    #[test]
    fn lowerdir_budget_accepts_normal_chains() {
        let lowers: Vec<PathBuf> = (0..10)
            .map(|i| PathBuf::from(format!("/var/lib/containerd-nydus/snapshots/{i}/fs")))
            .collect();
        assert!(ensure_lowerdir_budget(&lowers).is_ok());
    }

    #[test]
    fn lowerdir_budget_trusts_containerd_compaction_for_shared_prefixes() {
        // 200 lowerdirs under one snapshots root: raw ~9KB (over budget),
        // compacted ~1.2KB (under). Must pass, relying on containerd.
        let lowers: Vec<PathBuf> = (0..200)
            .map(|i| PathBuf::from(format!("/var/lib/containerd-nydus/snapshots/{i}/fs")))
            .collect();
        assert!(ensure_lowerdir_budget(&lowers).is_ok());
    }

    #[test]
    fn lowerdir_budget_rejects_chains_compaction_cannot_save() {
        // No common prefix beyond "/" and long unique names: even compacted
        // the option cannot fit in a page.
        let lowers: Vec<PathBuf> = (0..200)
            .map(|i| PathBuf::from(format!("/mnt-{i:03}/{}/fs", "x".repeat(60))))
            .collect();
        let err = ensure_lowerdir_budget(&lowers).unwrap_err();
        assert!(err.to_string().contains("too many layers"));
    }

    #[test]
    fn compacted_len_matches_relative_join() {
        let lowers = vec![
            PathBuf::from("/root/snapshots/1/fs"),
            PathBuf::from("/root/snapshots/22/fs"),
        ];
        // Relative to /root/snapshots: "1/fs" + ":" + "22/fs" = 10.
        assert_eq!(compacted_lowerdir_len(&lowers), 10);
    }
}
