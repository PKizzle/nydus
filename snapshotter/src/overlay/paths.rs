// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Stable on-disk path helpers for snapshot metadata and overlay directories.

use anyhow::{Context, Result, bail};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::warn;

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

/// Flat farm of short symlinks used only inside `lowerdir=` mount options,
/// mirroring Docker overlay2's `l/` directory. The snapshot dir names above
/// run ~65 chars and cost ~69 bytes per layer in the option string even after
/// containerd's common-prefix compaction, capping plain-overlay chains at
/// ~52 layers against the kernel's one-page mount-option limit. A 17-char
/// link per layer raises that ceiling to ~200; the kernel resolves the
/// symlinks during `mount(2)`, so the resulting overlay is identical.
pub(super) fn short_link_dir(root: &Path) -> PathBuf {
    root.join("l")
}

pub(super) fn short_link_name(key: &str) -> String {
    format!("{:016x}", fnv1a64(key.as_bytes()))
}

pub(super) fn short_link_path(root: &Path, key: &str) -> PathBuf {
    short_link_dir(root).join(short_link_name(key))
}

/// Target of a snapshot's short link, relative to `<root>/l/` so the whole
/// root stays relocatable.
fn short_link_target(key: &str) -> PathBuf {
    PathBuf::from("..")
        .join("snapshots")
        .join(snapshot_dir_name(key))
        .join("fs")
}

/// Ensure `<root>/l/<hash>` points at this snapshot's `fs/` dir and return
/// the link path. Idempotent; a same-name link pointing elsewhere means a
/// 64-bit FNV collision between live snapshot keys and is a hard error
/// (`snapshot_dir_name` disambiguates via its 48-char key suffix, the flat
/// link namespace cannot).
pub(super) fn ensure_short_link(root: &Path, key: &str) -> Result<PathBuf> {
    let link = short_link_path(root, key);
    let target = short_link_target(key);
    for _ in 0..2 {
        match fs::read_link(&link) {
            Ok(existing) if existing == target => return Ok(link),
            Ok(existing) => bail!(
                "short link {} already points at {} (expected {}); snapshot key hash collision",
                link.display(),
                existing.display(),
                target.display()
            ),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            // `readlink` answers EINVAL when the path exists but is not a
            // symlink -- a plain file or directory left by a botched restore or
            // a stray write. Nothing here ever creates one, and the name is
            // ours to own, so replace it rather than wedging every mount of
            // this snapshot behind an error no retry can clear.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                warn!(
                    link = %link.display(),
                    "short link path exists but is not a symlink; replacing it"
                );
                remove_short_link_path(&link)?;
            }
            Err(e) => {
                return Err(e).with_context(|| format!("read short link {}", link.display()));
            }
        }
        fs::create_dir_all(short_link_dir(root)).with_context(|| {
            format!(
                "create short link directory {}",
                short_link_dir(root).display()
            )
        })?;
        match std::os::unix::fs::symlink(&target, &link) {
            Ok(()) => return Ok(link),
            // Lost a creation race; loop once to validate the winner's target.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("create short link {}", link.display()));
            }
        }
    }
    bail!("short link {} kept changing underneath us", link.display())
}

/// Remove a snapshot's short link if present.
pub(super) fn remove_short_link(root: &Path, key: &str) -> Result<()> {
    remove_short_link_path(&short_link_path(root, key))
}

/// Unlink one short-link path, tolerating "already gone". A directory left at
/// the name (which nothing here creates) needs `remove_dir` instead.
fn remove_short_link_path(link: &Path) -> Result<()> {
    match fs::remove_file(link) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) if link.is_dir() => fs::remove_dir(link)
            .with_context(|| format!("remove short link directory {}", link.display())),
        Err(e) => Err(e).with_context(|| format!("remove short link {}", link.display())),
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
    fn ensure_short_link_creates_relative_link_and_is_idempotent() {
        let root = tempdir().unwrap();
        let key = "sha256:0123456789abcdef";
        fs::create_dir_all(fs_dir(root.path(), key)).unwrap();

        let link = ensure_short_link(root.path(), key).unwrap();
        assert_eq!(link, short_link_path(root.path(), key));
        assert_eq!(
            fs::read_link(&link).unwrap(),
            Path::new("..")
                .join("snapshots")
                .join(snapshot_dir_name(key))
                .join("fs")
        );
        // The relative target resolves to the real fs dir.
        assert_eq!(
            fs::canonicalize(&link).unwrap(),
            fs::canonicalize(fs_dir(root.path(), key)).unwrap()
        );
        // Idempotent.
        assert_eq!(ensure_short_link(root.path(), key).unwrap(), link);
    }

    #[test]
    fn ensure_short_link_rejects_hash_collisions() {
        let root = tempdir().unwrap();
        let key = "collision-key";
        fs::create_dir_all(short_link_dir(root.path())).unwrap();
        std::os::unix::fs::symlink("../snapshots/other/fs", short_link_path(root.path(), key))
            .unwrap();

        let err = ensure_short_link(root.path(), key).unwrap_err();
        assert!(err.to_string().contains("hash collision"), "{err}");
    }

    #[test]
    fn remove_short_link_tolerates_missing_link() {
        let root = tempdir().unwrap();
        let key = "never-linked";
        remove_short_link(root.path(), key).unwrap();

        fs::create_dir_all(fs_dir(root.path(), key)).unwrap();
        let link = ensure_short_link(root.path(), key).unwrap();
        remove_short_link(root.path(), key).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
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
