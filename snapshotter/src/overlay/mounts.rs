// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Containerd mount-spec helpers for bind and overlay mounts.

use containerd_snapshots::api::types::Mount;
use std::path::{Path, PathBuf};

pub(super) fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(":")
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
}
