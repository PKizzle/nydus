// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Stable on-disk path helpers for snapshot metadata and overlay directories.

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn snapshot_dir(root: &Path, key: &str) -> PathBuf {
    root.join("snapshots").join(snapshot_dir_name(key))
}

pub(super) fn fs_dir(root: &Path, key: &str) -> PathBuf {
    snapshot_dir(root, key).join("fs")
}

pub(super) fn work_dir(root: &Path, key: &str) -> PathBuf {
    snapshot_dir(root, key).join("work")
}

/// Return the stable on-disk directory name for a containerd snapshot key.
///
/// Migration code uses the same mapping to relocate legacy numeric snapshot
/// directories into the Rust snapshotter layout without asking containerd to
/// recreate every layer.
pub fn snapshot_dir_name(key: &str) -> String {
    let hash = fnv1a64(key.as_bytes());
    let mut sanitized = String::new();
    for ch in key.chars().take(48) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        format!("{hash:016x}")
    } else {
        format!("{hash:016x}-{sanitized}")
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001b3;

    bytes.iter().fold(FNV_OFFSET, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    })
}

pub(super) fn dir_usage(path: &Path) -> Result<(i64, i64)> {
    if !path.exists() {
        return Ok((0, 0));
    }

    let metadata = fs::symlink_metadata(path)?;
    let mut size = metadata.len() as i64;
    let mut inodes = 1i64;

    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let (entry_size, entry_inodes) = dir_usage(&entry.path())?;
            size += entry_size;
            inodes += entry_inodes;
        }
    }

    Ok((size, inodes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn snapshot_dir_name_is_stable_and_filesystem_safe() {
        assert_eq!(snapshot_dir_name("abc"), snapshot_dir_name("abc"));
        let name = snapshot_dir_name("k8s.io/ns/key/sha256:abc");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        );
    }

    #[test]
    fn path_helpers_use_snapshot_root() {
        let root = Path::new("/var/lib/containerd-nydus");
        let snap = snapshot_dir(root, "active");
        assert!(snap.starts_with(root.join("snapshots")));
        assert_eq!(fs_dir(root, "active"), snap.join("fs"));
        assert_eq!(work_dir(root, "active"), snap.join("work"));
    }

    #[test]
    fn dir_usage_counts_files() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("file"), b"hello").unwrap();
        let (size, inodes) = dir_usage(dir.path()).unwrap();
        assert!(size >= 5);
        assert!(inodes >= 2);
    }
}
