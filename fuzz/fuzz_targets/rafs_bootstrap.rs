//! RAFS v5/v6 bootstrap loading: superblocks, inode/blob/chunk tables, the prefetch table, and
//! a whole-tree walk, through the same `RafsSuper::load_from_file` call nydusd mounts with.
#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use nydus_api::ConfigV2;
use nydus_rafs::RafsIterator;
use nydus_rafs::metadata::RafsSuper;

mod common;

fuzz_target!(|data: &[u8]| {
    let path = common::write_input("bootstrap", data);
    let Ok((sb, mut reader)) =
        RafsSuper::load_from_file(&path, Arc::new(ConfigV2::default()), false)
    else {
        return;
    };
    let _ = sb.get_prefetched_inos(&mut reader);
    let _ = sb.superblock.get_blob_extra_infos();
    for (inode, _) in RafsIterator::new(&sb) {
        common::touch_inode(&sb, inode.as_inode());
        let _ = sb.path_from_ino(inode.ino());
    }
});
