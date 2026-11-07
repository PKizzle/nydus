//! Helpers shared by the fuzz targets.
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;

use nydus_rafs::metadata::{RafsInode, RafsInodeExt, RafsInodeWalkAction, RafsSuper};

/// Write `data` to a per-process scratch file named `name` and return its path.
///
/// The RAFS and blob-meta loaders only accept file paths (they mmap what they load), so each
/// input goes through a file; it is rewritten in place on every iteration.
pub fn write_input(name: &str, data: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nydus-fuzz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create fuzz scratch dir");
    let path = dir.join(name);
    std::fs::write(&path, data).expect("write fuzz input");
    path
}

/// Exercise the accessors the FUSE server calls on an inode, ignoring their errors: the fuzzer
/// looks for panics and memory errors, not for well-formed answers.
pub fn touch_inode(sb: &RafsSuper, inode: &dyn RafsInode) {
    let _ = inode.validate(sb.get_max_ino(), sb.meta.chunk_size as u64);
    let _ = inode.get_attr();
    let _ = inode.get_entry();
    if inode.is_symlink() {
        let _ = inode.get_symlink();
    }
    if inode.has_xattr()
        && let Ok(names) = inode.get_xattrs()
    {
        for name in names {
            let _ = inode.get_xattr(OsStr::from_bytes(&name));
        }
    }
}

/// List a directory the way `readdir` does and look every listed name up again.
pub fn readdir_and_lookup(dir: &Arc<dyn RafsInodeExt>) {
    let mut names: Vec<OsString> = Vec::new();
    let _ = dir.walk_children_inodes(0, &mut |_, name, _, _| {
        names.push(name);
        Ok(RafsInodeWalkAction::Continue)
    });
    for name in names {
        let _ = dir.get_child_by_name(&name);
    }
}
