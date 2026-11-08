// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::mem::size_of;
use std::sync::Arc;

use super::direct_v6::DirectSuperBlockV6;
use super::layout::RAFS_SUPER_VERSION_V6;
use super::layout::v6::{
    EROFS_BLOCK_SIZE_4096, RafsV6PrefetchTable, RafsV6SuperBlock, RafsV6SuperBlockExt,
};
use super::*;
use super::{RafsMode, RafsSuper, RafsSuperBlock, RafsSuperFlags};

use crate::RafsIoReader;
use crate::{RafsError, RafsResult};

/// The validated superblocks of a RAFS v6 bootstrap.
#[derive(Clone, Copy)]
pub(crate) struct V6Superblocks {
    pub sb: RafsV6SuperBlock,
    pub ext: RafsV6SuperBlockExt,
}

/// Load and validate the superblocks of the bootstrap `r`, or `None` if `r` is not a RAFS v6
/// bootstrap.
pub(crate) fn load_v6_superblocks(r: &mut RafsIoReader) -> RafsResult<Option<V6Superblocks>> {
    let end = r.seek_to_end(0)?;
    r.seek_to_offset(0)?;

    let mut sb = RafsV6SuperBlock::new();
    if sb.load(r).is_err() || !sb.is_rafs_v6() {
        return Ok(None);
    }
    let block_size = sb.validate(end)?;
    let mut ext_sb = RafsV6SuperBlockExt::new();
    ext_sb.load(r)?;
    let xattr_prefix_size = sb.load_xattr_prefix_table_size(r, end)?;
    r.seek_to_offset(EROFS_BLOCK_SIZE_4096)?;
    ext_sb.validate(end, &sb, block_size, xattr_prefix_size)?;
    Ok(Some(V6Superblocks { sb, ext: ext_sb }))
}

impl RafsSuper {
    pub(crate) fn try_load_v6(&mut self, r: &mut RafsIoReader) -> RafsResult<bool> {
        let Some(superblocks) = load_v6_superblocks(r)? else {
            return Ok(false);
        };
        let V6Superblocks { sb, ext: ext_sb } = superblocks;
        self.meta.version = RAFS_SUPER_VERSION_V6;
        self.meta.magic = sb.magic();
        self.meta.meta_blkaddr = sb.meta_addr();
        self.meta.root_nid = sb.root_nid();
        self.meta.blkszbits = sb.blkszbits();
        self.meta.blob_device_table_count = sb.extra_devices() as u32;
        self.meta.blob_device_table_offset = sb.device_table_offset();

        self.meta.chunk_size = ext_sb.chunk_size();
        self.meta.blob_table_offset = ext_sb.blob_table_offset();
        self.meta.blob_table_size = ext_sb.blob_table_size();
        self.meta.chunk_table_offset = ext_sb.chunk_table_offset();
        self.meta.chunk_table_size = ext_sb.chunk_table_size();
        self.meta.inodes_count = sb.inodes_count();

        self.meta.flags = RafsSuperFlags::from_bits(ext_sb.flags()).ok_or_else(|| {
            RafsError::InvalidMetadata(format!("invalid RAFS flags 0x{:x}", ext_sb.flags()))
        })?;
        info!("RAFS features: {}", self.meta.flags);

        let (prefetch_offset, prefetch_size) = ext_sb.prefetch_table();
        self.meta.prefetch_table_entries = prefetch_size / size_of::<u32>() as u32;
        self.meta.prefetch_table_offset = prefetch_offset;
        trace!(
            "prefetch table offset {} entries {} ",
            self.meta.prefetch_table_offset, self.meta.prefetch_table_entries
        );

        if ext_sb.implicit_dir_table_size() > 0 {
            let mut table = RafsV6PrefetchTable::new();
            table.load_prefetch_table_from(
                r,
                ext_sb.implicit_dir_table_offset(),
                ext_sb.implicit_dir_table_size() as usize / size_of::<u32>(),
            )?;
            self.implicit_dirs = table.inodes;
            self.implicit_dirs.sort_unstable();
            r.seek_to_offset(EROFS_BLOCK_SIZE_4096)?;
        }

        match self.mode {
            RafsMode::Direct => {
                let mut sb_v6 = DirectSuperBlockV6::new(&self.meta, superblocks);
                sb_v6.load(r)?;
                self.superblock = Arc::new(sb_v6);
                Ok(true)
            }
            RafsMode::Cached => Err(RafsError::Unsupported),
        }
    }

    pub(crate) fn is_inlay_prefetch_all(&self, r: &mut RafsIoReader) -> RafsResult<bool> {
        let hint_entries = self.meta.prefetch_table_entries as usize;
        if hint_entries != 1 {
            return Ok(false);
        }
        let unique = if self.meta.is_v6() {
            let mut prefetch_table = RafsV6PrefetchTable::new();
            prefetch_table
                .load_prefetch_table_from(r, self.meta.prefetch_table_offset, hint_entries)
                .map_err(|e| {
                    RafsError::Prefetch(format!(
                        "Failed in loading hint prefetch table at offset {}. {:?}",
                        self.meta.prefetch_table_offset, e
                    ))
                })?;
            prefetch_table.inodes[0] as u64
        } else {
            let mut prefetch_table = RafsV5PrefetchTable::new();
            prefetch_table
                .load_prefetch_table_from(r, self.meta.prefetch_table_offset, hint_entries)
                .map_err(|e| {
                    RafsError::Prefetch(format!(
                        "Failed in loading hint prefetch table at offset {}. {:?}",
                        self.meta.prefetch_table_offset, e
                    ))
                })?;
            prefetch_table.inodes[0] as u64
        };

        Ok(unique == self.superblock.root_ino())
    }

    pub(crate) fn prefetch_data_v6<F>(
        &self,
        device: &BlobDevice,
        r: &mut RafsIoReader,
        root_ino: Inode,
        fetcher: F,
    ) -> RafsResult<bool>
    where
        F: Fn(&mut BlobIoVec, bool),
    {
        let hint_entries = self.meta.prefetch_table_entries as usize;
        if hint_entries == 0 {
            return Ok(false);
        }

        // Try to prefetch according to the list of files specified by the
        // builder's `--prefetch-policy fs` option.
        let mut prefetch_table = RafsV6PrefetchTable::new();
        prefetch_table
            .load_prefetch_table_from(r, self.meta.prefetch_table_offset, hint_entries)
            .map_err(|e| {
                RafsError::Prefetch(format!(
                    "Failed in loading hint prefetch table at offset {}. {:?}",
                    self.meta.prefetch_table_offset, e
                ))
            })?;
        trace!("prefetch table contents {:?}", prefetch_table);

        let mut hardlinks: HashSet<u64> = HashSet::new();
        let mut state = BlobIoMerge::default();
        let mut found_root_inode = false;
        for ino in prefetch_table.inodes {
            // Inode number 0 is invalid, it was added because prefetch table has to be aligned.
            if ino == 0 {
                break;
            }
            if ino as Inode == root_ino {
                found_root_inode = true;
            }
            trace!("hint prefetch inode {}", ino);
            self.prefetch_data(device, ino as u64, &mut state, &mut hardlinks, &fetcher)
                .map_err(|e| RafsError::Prefetch(e.to_string()))?;
        }
        // The left chunks whose size is smaller than 4MB will be fetched here.
        for (_id, mut desc) in state.drain() {
            fetcher(&mut desc, true);
        }

        Ok(found_root_inode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BufWriter;
    use crate::metadata::RafsStore;
    use std::fs::OpenOptions;
    use std::io::Write;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_v6_load_too_small_superblock() {
        let t_file = TempFile::new().unwrap();

        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(t_file.as_path())
            .unwrap();
        let mut reader = Box::new(file) as RafsIoReader;
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: true,
            ..Default::default()
        };

        assert!(!rs.try_load_v6(&mut reader).unwrap());
    }

    #[test]
    fn test_v6_load_invalid_magic() {
        let t_file = TempFile::new().unwrap();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(t_file.as_path())
            .unwrap();
        file.write_all(&[0u8; 4096]).unwrap();
        let mut reader = Box::new(file) as RafsIoReader;
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: true,
            ..Default::default()
        };

        assert!(!rs.try_load_v6(&mut reader).unwrap());
    }

    #[test]
    fn test_v6_load_invalid_superblock() {
        let t_file = TempFile::new().unwrap();

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(t_file.as_path())
            .unwrap();
        let sb = RafsV6SuperBlock::new();
        let mut writer = BufWriter::new(file);
        sb.store(&mut writer).unwrap();
        writer.flush().unwrap();

        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(t_file.as_path())
            .unwrap();
        let mut reader = Box::new(file) as RafsIoReader;
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: true,
            ..Default::default()
        };

        assert!(rs.try_load_v6(&mut reader).is_err());
    }

    /// Run `try_load_v6` over a bootstrap holding only `sb` and `ext`.
    fn load_crafted(
        sb: &RafsV6SuperBlock,
        ext: &RafsV6SuperBlockExt,
    ) -> (RafsSuper, RafsResult<bool>) {
        use crate::metadata::layout::v6::test_util::DEVSLOT_TEST_END;
        use crate::metadata::layout::v6::{EROFS_SUPER_BLOCK_SIZE, EROFS_SUPER_OFFSET};

        let t_file = TempFile::new().unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(t_file.as_path())
            .unwrap();
        let mut writer = BufWriter::new(file.try_clone().unwrap());
        sb.store(&mut writer).unwrap();
        writer
            .seek_offset((EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as u64)
            .unwrap();
        ext.store(&mut writer).unwrap();
        writer.flush().unwrap();
        file.set_len(DEVSLOT_TEST_END).unwrap();

        let mut reader = Box::new(file) as RafsIoReader;
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            ..Default::default()
        };
        rs.meta.metadata_source = crate::test_util::METADATA_SOURCE;
        let result = rs.try_load_v6(&mut reader);
        (rs, result)
    }

    #[test]
    fn test_v6_load_rejects_blob_table_in_devslots() {
        use crate::metadata::layout::v6::test_util::{test_ext_sb, test_sb};

        // 54 device slots run 128 bytes past the 8 KiB boundary the blob table starts at.
        let sb = test_sb(54, 24 * EROFS_BLOCK_SIZE_4096);
        let ext = test_ext_sb(2 * EROFS_BLOCK_SIZE_4096, 54);
        let err = load_crafted(&sb, &ext).1.unwrap_err();
        assert!(
            matches!(&err, RafsError::InvalidMetadata(msg) if msg.contains("blob table offset")),
            "{err:?}"
        );
    }

    #[test]
    fn test_v6_load_ignores_legacy_prefetch_table_at_offset_0() {
        use crate::metadata::layout::v6::test_util::{test_ext_sb, test_sb};

        let sb = test_sb(0, 2 * EROFS_BLOCK_SIZE_4096);
        let mut ext = test_ext_sb(EROFS_BLOCK_SIZE_4096, 0);
        ext.set_prefetch_table_size(4);
        // Loading fails later on the empty inode area; the prefetch entries are set before.
        let (rs, _) = load_crafted(&sb, &ext);
        assert_eq!(rs.meta.prefetch_table_entries, 0);
        ext.set_prefetch_table_offset(EROFS_BLOCK_SIZE_4096);
        let (rs, _) = load_crafted(&sb, &ext);
        assert_eq!(rs.meta.prefetch_table_entries, 1);
    }

    /*
    #[test]
    fn test_try_load_v6() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6.boot");

        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(source_path)
            .unwrap();
        let mut reader = Box::new(file) as RafsIoReader;
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: true,
            ..Default::default()
        };

        rs.try_load_v6(&mut reader).unwrap();
    }
     */
}
