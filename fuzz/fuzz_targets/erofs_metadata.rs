//! RAFS v6 (EROFS) on-disk metadata as the FUSE server reads it: inodes, dirent blocks
//! (`readdir` and name lookup), xattrs, symlinks and chunk-index tables, reached from the root
//! by lookups rather than by a precomputed walk.
#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use nydus_api::ConfigV2;
use nydus_rafs::metadata::RafsSuper;

mod common;

/// Directories visited per input; bounds the work a deep or cyclic tree can cause.
const MAX_DIRS: usize = 256;
/// Chunk-table entries resolved per regular file.
const MAX_CHUNKS: u32 = 64;

fuzz_target!(|data: &[u8]| {
    let path = common::write_input("bootstrap", data);
    let Ok((sb, _)) = RafsSuper::load_from_file(&path, Arc::new(ConfigV2::default()), false) else {
        return;
    };
    if !sb.meta.is_v6() {
        return;
    }
    let Ok(root) = sb.get_extended_inode(sb.superblock.root_ino(), false) else {
        return;
    };
    let mut dirs = vec![root];
    let mut visited = 0;
    while let Some(dir) = dirs.pop() {
        visited += 1;
        if visited > MAX_DIRS {
            break;
        }
        common::touch_inode(&sb, dir.as_inode());
        common::readdir_and_lookup(&dir);
        let _ = dir.get_child_index();
        for idx in 0..dir.get_child_count().min(MAX_DIRS as u32) {
            let Ok(child) = dir.get_child_by_index(idx) else {
                continue;
            };
            common::touch_inode(&sb, child.as_inode());
            let _ = child.name();
            let _ = child.parent();
            if child.is_dir() {
                dirs.push(child);
            } else if child.is_reg() {
                let _ = child.get_digest();
                for c in 0..child.get_chunk_count().min(MAX_CHUNKS) {
                    let _ = child.get_chunk_info(c);
                }
            }
        }
    }
});
