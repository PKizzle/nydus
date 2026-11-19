// Copyright 2021 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A chunk state tracking driver based on a bitmap file.
//!
//! This module provides a chunk state tracking driver based on a bitmap file. There's a state bit
//! in the bitmap file for each chunk, and atomic operations are used to manipulate the bitmap.
//! So it supports concurrent downloading.

use crate::cache::state::persist_map::PersistMap;
use crate::cache::state::{ChunkIndexGetter, ChunkMap, RangeMap};
use crate::device::BlobChunkInfo;
use crate::{StorageError, StorageResult};

/// The name suffix of blob chunk_map file, named $blob_id.chunk_map.
const FILE_SUFFIX: &str = "chunk_map";

/// An implementation of [ChunkMap] to support chunk state tracking by using a bitmap file.
///
/// The `IndexedChunkMap` is an implementation of [ChunkMap] which uses a bitmap file and atomic
/// bitmap operations to track readiness state. It creates or opens a file with the name
/// `$blob_id.chunk_map` to record whether a chunk has been cached by the blob cache, and atomic
/// bitmap operations are used to manipulate the state bit. The bitmap file will be persisted to
/// disk.
///
/// This approach can be used to share chunk ready state between multiple nydusd instances.
/// For example: the bitmap file layout is [0b00000000, 0b00000000], when blobcache calls
/// set_ready(3), the layout should be changed to [0b00010000, 0b00000000].
pub struct IndexedChunkMap {
    map: PersistMap,
}

impl IndexedChunkMap {
    /// Create a new instance of `IndexedChunkMap`.
    pub fn new(blob_path: &str, chunk_count: u32, persist: bool) -> StorageResult<Self> {
        let filename = format!("{}.{}", blob_path, FILE_SUFFIX);

        PersistMap::open(&filename, chunk_count, true, persist).map(|map| IndexedChunkMap { map })
    }
}

impl ChunkMap for IndexedChunkMap {
    fn is_ready(&self, chunk: &dyn BlobChunkInfo) -> StorageResult<bool> {
        if self.is_range_all_ready() {
            Ok(true)
        } else {
            let index = self.map.validate_index(chunk.id())?;
            Ok(self.map.is_chunk_ready(index).0)
        }
    }

    fn set_ready_and_clear_pending(&self, chunk: &dyn BlobChunkInfo) -> StorageResult<()> {
        self.map.set_chunk_ready(chunk.id())
    }

    fn is_persist(&self) -> bool {
        true
    }

    fn as_range_map(&self) -> Option<&dyn RangeMap<I = u32>> {
        Some(self)
    }
}

impl RangeMap for IndexedChunkMap {
    type I = u32;

    #[inline]
    fn is_range_all_ready(&self) -> bool {
        self.map.is_range_all_ready()
    }

    fn reset_range_ready(&self) -> StorageResult<()> {
        self.map.reset()
    }

    fn clear_ready(&self, index: u32) -> StorageResult<()> {
        self.map.clear_chunk_ready(index)
    }

    fn is_verified(&self, data_stamp: u64) -> bool {
        self.map.is_verified(data_stamp)
    }

    fn is_none_ready(&self) -> bool {
        self.map.ready_chunks() == 0
    }

    fn set_verified(&self, data_stamp: Option<u64>) -> StorageResult<()> {
        self.map.set_verified(data_stamp)
    }

    fn update_data_stamp(&self, data_stamp: u64) -> StorageResult<()> {
        self.map.update_data_stamp(data_stamp)
    }

    fn adopt_boot(&self, boot: u64, forget_untrusted: bool) -> StorageResult<bool> {
        self.map.adopt_boot(boot, forget_untrusted)
    }

    fn mark_unsealed(&self) -> StorageResult<()> {
        self.map.mark_unsealed()
    }

    fn seal(&self, flush: &mut dyn FnMut() -> StorageResult<Option<u64>>) -> StorageResult<bool> {
        self.map.seal(flush)
    }

    fn is_rechecking(&self) -> bool {
        self.map.is_rechecking()
    }

    fn is_range_ready(&self, start_index: u32, count: u32) -> StorageResult<bool> {
        if !self.is_range_all_ready() {
            for idx in 0..count {
                let index = self
                    .map
                    .validate_index(start_index.checked_add(idx).ok_or_else(|| {
                        StorageError::InvalidArgument("chunk index overflowed".to_string())
                    })?)?;
                if !self.map.is_chunk_ready(index).0 {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    fn check_range_ready_and_mark_pending(
        &self,
        start_index: u32,
        count: u32,
    ) -> StorageResult<Option<Vec<u32>>> {
        if self.is_range_all_ready() {
            return Ok(None);
        }

        let mut vec = Vec::with_capacity(count as usize);
        let count = std::cmp::min(count, u32::MAX - start_index);
        let end = start_index + count;

        for index in start_index..end {
            if !self.map.is_chunk_ready(index).0 {
                vec.push(index);
            }
        }

        if vec.is_empty() {
            Ok(None)
        } else {
            Ok(Some(vec))
        }
    }

    fn set_range_ready_and_clear_pending(&self, start_index: u32, count: u32) -> StorageResult<()> {
        let count = std::cmp::min(count, u32::MAX - start_index);
        let end = start_index + count;

        for index in start_index..end {
            self.map.set_chunk_ready(index)?;
        }

        Ok(())
    }
}

impl ChunkIndexGetter for IndexedChunkMap {
    type Index = u32;

    fn get_index(chunk: &dyn BlobChunkInfo) -> Self::Index {
        chunk.id()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::atomic::Ordering;
    use tempfile::TempDir;

    use super::super::persist_map::*;
    use super::*;
    use crate::device::v5::BlobV5ChunkInfo;
    use crate::test::MockChunkInfo;

    #[test]
    fn test_indexed_new_invalid_file_size() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0, false).is_err());

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_path)
            .map_err(|err| {
                StorageError::InvalidArgument(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })
            .unwrap();
        file.write_all(&[0x0u8]).unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        assert!(IndexedChunkMap::new(&blob_path, 1, true).is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_indexed_new_zero_file_size() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0, true).is_err());

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let _file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_path)
            .map_err(|err| {
                StorageError::InvalidArgument(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })
            .unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        let map = IndexedChunkMap::new(&blob_path, 1, true).unwrap();
        assert_eq!(map.map.not_ready_count.load(Ordering::Acquire), 1);
        assert_eq!(map.map.count, 1);
        assert_eq!(map.map.size(), 0x1001);
        assert!(!map.is_range_all_ready());
        assert!(!map.is_ready(chunk.as_base()).unwrap());
        map.set_ready_and_clear_pending(chunk.as_base()).unwrap();
        assert!(map.is_ready(chunk.as_base()).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_indexed_new_header_not_ready() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0, true).is_err());

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_path)
            .map_err(|err| {
                StorageError::InvalidArgument(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })
            .unwrap();
        file.set_len(0x1001).unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        let map = IndexedChunkMap::new(&blob_path, 1, true).unwrap();
        assert_eq!(map.map.not_ready_count.load(Ordering::Acquire), 1);
        assert_eq!(map.map.count, 1);
        assert_eq!(map.map.size(), 0x1001);
        assert!(!map.is_range_all_ready());
        assert!(!map.is_ready(chunk.as_base()).unwrap());
        map.set_ready_and_clear_pending(chunk.as_base()).unwrap();
        assert!(map.is_ready(chunk.as_base()).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_indexed_new_all_ready() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0, true).is_err());

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_path)
            .map_err(|err| {
                StorageError::InvalidArgument(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })
            .unwrap();
        let header = Header {
            magic: MAGIC1,
            version: 1,
            magic2: MAGIC2,
            all_ready: MAGIC_ALL_READY,
            verified: 0,
            ready_count: 0,
            data_stamp: 0,
            unsealed_boot: 0,
            recheck: 0,
            tracked: 0,
            reserved: [0x0u8; HEADER_RESERVED_SIZE],
        };

        // write file header and sync to disk.
        file.write_all(header.as_slice()).unwrap();
        file.write_all(&[0x0u8]).unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        let map = IndexedChunkMap::new(&blob_path, 1, true).unwrap();
        assert!(map.is_range_all_ready());
        assert_eq!(map.map.count, 1);
        assert_eq!(map.map.size(), 0x1001);
        assert!(map.is_ready(chunk.as_base()).unwrap());
        map.set_ready_and_clear_pending(chunk.as_base()).unwrap();
        assert!(map.is_ready(chunk.as_base()).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_indexed_new_load_v0() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0, true).is_err());

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_path)
            .map_err(|err| {
                StorageError::InvalidArgument(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })
            .unwrap();
        let header = Header {
            magic: MAGIC1,
            version: 0,
            magic2: 0,
            all_ready: 0,
            verified: 0,
            ready_count: 0,
            data_stamp: 0,
            unsealed_boot: 0,
            recheck: 0,
            tracked: 0,
            reserved: [0x0u8; HEADER_RESERVED_SIZE],
        };

        // write file header and sync to disk.
        file.write_all(header.as_slice()).unwrap();
        file.write_all(&[0x0u8]).unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        let map = IndexedChunkMap::new(&blob_path, 1, true).unwrap();
        assert_eq!(map.map.not_ready_count.load(Ordering::Acquire), 1);
        assert_eq!(map.map.count, 1);
        assert_eq!(map.map.size(), 0x1001);
        assert!(!map.is_range_all_ready());
        assert!(!map.is_ready(chunk.as_base()).unwrap());
        map.set_ready_and_clear_pending(chunk.as_base()).unwrap();
        assert!(map.is_ready(chunk.as_base()).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_reset_revokes_every_chunk() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-reset");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        let map = IndexedChunkMap::new(&blob_path, 16, true).unwrap();
        for idx in 0..16u32 {
            let chunk = MockChunkInfo {
                index: idx,
                ..Default::default()
            };
            map.set_ready_and_clear_pending(chunk.as_base()).unwrap();
        }
        assert!(map.is_range_all_ready());
        assert_eq!(map.map.not_ready_count.load(Ordering::Acquire), 0);

        map.reset_range_ready().unwrap();

        // Both views of readiness must agree: the `all_ready` short circuit *and* the
        // per-chunk bits. Clearing only the header would leave `is_ready(i)` answering true
        // for a chunk whose bytes are gone.
        assert!(!map.is_range_all_ready());
        assert_eq!(map.map.not_ready_count.load(Ordering::Acquire), 16);
        for idx in 0..16u32 {
            let chunk = MockChunkInfo {
                index: idx,
                ..Default::default()
            };
            assert!(
                !map.is_ready(chunk.as_base()).unwrap(),
                "chunk {idx} still claimed ready after reset"
            );
        }

        // And the map is still usable afterwards, not left in a wedged state.
        let chunk = MockChunkInfo {
            index: 3,
            ..Default::default()
        };
        map.set_ready_and_clear_pending(chunk.as_base()).unwrap();
        assert!(map.is_ready(chunk.as_base()).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_reset_survives_reopen() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-reset-persist");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        {
            let map = IndexedChunkMap::new(&blob_path, 8, true).unwrap();
            for idx in 0..8u32 {
                let chunk = MockChunkInfo {
                    index: idx,
                    ..Default::default()
                };
                map.set_ready_and_clear_pending(chunk.as_base()).unwrap();
            }
            assert!(map.is_range_all_ready());
            map.reset_range_ready().unwrap();
        }

        // A reset that only lived in the mmap would come back "all ready" here, and the
        // discarded bytes would be served as zeros after a restart.
        let reopened = IndexedChunkMap::new(&blob_path, 8, true).unwrap();
        assert!(!reopened.is_range_all_ready());
        assert_eq!(reopened.map.not_ready_count.load(Ordering::Acquire), 8);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_clear_ready_and_verified_survive_reopen() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-clear");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let chunk = |index| MockChunkInfo {
            index,
            ..Default::default()
        };

        {
            let map = IndexedChunkMap::new(&blob_path, 8, true).unwrap();
            assert!(!map.is_verified(7));
            for idx in 0..8u32 {
                map.set_ready_and_clear_pending(chunk(idx).as_base())
                    .unwrap();
            }
            assert!(map.is_range_all_ready());
            map.clear_ready(5).unwrap();
            assert!(!map.is_range_all_ready());
            assert!(!map.is_ready(chunk(5).as_base()).unwrap());
            assert!(map.is_ready(chunk(4).as_base()).unwrap());
            // Clearing a chunk that is not ready changes nothing.
            map.clear_ready(5).unwrap();
            assert_eq!(map.map.not_ready_count.load(Ordering::Acquire), 1);
            map.set_verified(Some(7)).unwrap();
        }

        let reopened = IndexedChunkMap::new(&blob_path, 8, true).unwrap();
        assert!(reopened.is_verified(7));
        // A data file changed since, by anyone, is not verified.
        assert!(!reopened.is_verified(8));
        assert!(!reopened.is_ready(chunk(5).as_base()).unwrap());
        assert_eq!(reopened.map.not_ready_count.load(Ordering::Acquire), 1);
        reopened.set_verified(None).unwrap();
        assert!(
            !IndexedChunkMap::new(&blob_path, 8, true)
                .unwrap()
                .is_verified(7)
        );
    }

    /// A release without fill validation sets ready bits but leaves the header's ready count
    /// alone, so a verified map it filled no longer reads as verified.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_verified_does_not_survive_a_fill_by_an_older_release() {
        use std::os::unix::fs::FileExt;

        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-old-fill");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let chunk = |index| MockChunkInfo {
            index,
            ..Default::default()
        };
        {
            let map = IndexedChunkMap::new(&blob_path, 16, true).unwrap();
            map.set_ready_and_clear_pending(chunk(0).as_base()).unwrap();
            map.set_verified(Some(7)).unwrap();
            // Fills by this version keep the record.
            map.set_ready_and_clear_pending(chunk(1).as_base()).unwrap();
            map.clear_ready(0).unwrap();
            assert!(map.is_verified(7));
        }
        assert!(
            IndexedChunkMap::new(&blob_path, 16, true)
                .unwrap()
                .is_verified(7)
        );

        // What an older release does on a fill: set the bit, nothing else.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("{blob_path}.chunk_map"))
            .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact_at(&mut byte, HEADER_SIZE as u64 + 1)
            .unwrap();
        file.write_all_at(&[byte[0] | 0x80], HEADER_SIZE as u64 + 1)
            .unwrap();
        drop(file);

        let map = IndexedChunkMap::new(&blob_path, 16, true).unwrap();
        assert!(map.is_ready(chunk(8).as_base()).unwrap());
        assert!(!map.is_verified(7));
        map.set_verified(Some(7)).unwrap();
        assert!(map.is_verified(7));
    }

    /// Every block of a chunk map is allocated when it is opened, new or left sparse by an older
    /// release: the bitmap is written through a shared mapping, where a store into a hole on a
    /// full file system raises SIGBUS instead of returning an error.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_map_has_no_holes() {
        use std::os::unix::fs::MetadataExt;

        // Allocated blocks, not SEEK_HOLE: ext4 and btrfs report fallocated (unwritten) extents
        // as holes there, although their blocks are reserved.
        let no_holes = |path: &str| {
            let md = std::fs::metadata(path).unwrap();
            assert!(
                md.blocks() * 512 >= md.len(),
                "{path}: {} bytes allocated of {}",
                md.blocks() * 512,
                md.len()
            );
        };
        let dir = TempDir::new().unwrap();
        // A bitmap spanning several file system blocks.
        let chunks = 8 * 3 * 4096;

        let new = dir.path().join("blob-new").to_str().unwrap().to_string();
        let map = IndexedChunkMap::new(&new, chunks, true).unwrap();
        no_holes(&format!("{new}.{FILE_SUFFIX}"));
        drop(map);

        let old = dir.path().join("blob-old").to_str().unwrap().to_string();
        let path = format!("{old}.{FILE_SUFFIX}");
        let mut file = std::fs::File::create(&path).unwrap();
        let header = Header {
            magic: MAGIC1,
            version: 1,
            magic2: MAGIC2,
            all_ready: 0,
            verified: 0,
            ready_count: 0,
            data_stamp: 0,
            unsealed_boot: 0,
            recheck: 0,
            tracked: 0,
            reserved: [0x0u8; HEADER_RESERVED_SIZE],
        };
        file.write_all(header.as_slice()).unwrap();
        file.set_len(HEADER_SIZE as u64 + chunks as u64 / 8)
            .unwrap();
        drop(file);
        let map = IndexedChunkMap::new(&old, chunks, true).unwrap();
        no_holes(&path);
        assert!(!map.is_range_all_ready());
    }

    /// A chunk map with a damaged header is replaced by an empty one, not refused: refusing
    /// fails the blob's open on every start. A process that still maps the old file keeps it
    /// intact. A map of the wrong size is still refused, since a live opener with another chunk
    /// count may be using it.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_corrupt_map_is_recreated() {
        use std::os::unix::fs::FileExt;

        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-corrupt");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let map_path = format!("{blob_path}.{FILE_SUFFIX}");
        let chunk = |index| MockChunkInfo {
            index,
            ..Default::default()
        };
        let filled = || {
            let map = IndexedChunkMap::new(&blob_path, 64, true).unwrap();
            for idx in 0..64u32 {
                map.set_ready_and_clear_pending(chunk(idx).as_base())
                    .unwrap();
            }
            map.set_verified(Some(7)).unwrap();
            map
        };
        let assert_fresh = || {
            let map = IndexedChunkMap::new(&blob_path, 64, true).unwrap();
            assert!(!map.is_range_all_ready());
            assert!(!map.is_verified(7));
            for idx in 0..64u32 {
                assert!(!map.is_ready(chunk(idx).as_base()).unwrap());
            }
            map.set_ready_and_clear_pending(chunk(3).as_base()).unwrap();
            assert!(map.is_ready(chunk(3).as_base()).unwrap());
        };

        // Wrong size.
        let live = filled();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&map_path)
            .unwrap();
        file.set_len(HEADER_SIZE as u64 + 4).unwrap();
        drop(file);
        drop(live);
        assert!(IndexedChunkMap::new(&blob_path, 64, true).is_err());
        std::fs::remove_file(&map_path).unwrap();

        // Damaged magic.
        let live = filled();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&map_path)
            .unwrap();
        file.write_all_at(&[0xff; 4], 0).unwrap();
        drop(file);
        drop(live);
        assert_fresh();

        // Damaged second magic, while another opener still maps the old file.
        let live = filled();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&map_path)
            .unwrap();
        file.write_all_at(&[0xff; 4], 8).unwrap();
        drop(file);
        assert_fresh();
        assert!(live.is_ready(chunk(10).as_base()).unwrap());
        assert!(live.is_range_all_ready());

        // An opener that may not create the map still refuses a damaged one.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&map_path)
            .unwrap();
        file.write_all_at(&[0xff; 4], 8).unwrap();
        drop(file);
        assert!(PersistMap::open(&map_path, 64, false, true).is_err());
    }

    /// The boot that left `blob_path`'s map unsealed, read from the file.
    fn unsealed_boot_on_disk(blob_path: &str) -> u64 {
        use std::os::unix::fs::FileExt;
        let mut word = [0u8; 8];
        std::fs::File::open(format!("{blob_path}.chunk_map"))
            .unwrap()
            .read_exact_at(
                &mut word,
                std::mem::offset_of!(Header, unsealed_boot) as u64,
            )
            .unwrap();
        u64::from_ne_bytes(word)
    }

    /// A map tracking boots records its boot before a ready bit and a seal clears it; a map
    /// whose opener does not track boots never records one.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_a_ready_bit_unseals_the_map_until_a_seal() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-seal");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let chunk = |index| MockChunkInfo {
            index,
            ..Default::default()
        };

        let map = IndexedChunkMap::new(&blob_path, 8, true).unwrap();
        map.set_ready_and_clear_pending(chunk(0).as_base()).unwrap();
        assert_eq!(unsealed_boot_on_disk(&blob_path), 0);
        // Nothing to seal.
        assert!(!map.seal(&mut || panic!("flushed a sealed map")).unwrap());

        assert!(!map.adopt_boot(7, true).unwrap());
        assert!(map.is_ready(chunk(0).as_base()).unwrap());
        map.mark_unsealed().unwrap();
        assert_eq!(unsealed_boot_on_disk(&blob_path), 7);
        assert!(map.seal(&mut || Ok(None)).unwrap());
        assert_eq!(unsealed_boot_on_disk(&blob_path), 0);
        map.set_ready_and_clear_pending(chunk(1).as_base()).unwrap();
        assert_eq!(unsealed_boot_on_disk(&blob_path), 7);

        // A failed flush leaves the map unsealed.
        assert!(map.seal(&mut || Err(StorageError::Unsupported)).is_err());
        assert_eq!(unsealed_boot_on_disk(&blob_path), 7);

        // The stamp follows the flush only for a verified map with a current ready count.
        assert!(map.seal(&mut || Ok(Some(9))).unwrap());
        assert!(!map.is_verified(9));
        map.set_verified(Some(5)).unwrap();
        map.set_ready_and_clear_pending(chunk(2).as_base()).unwrap();
        assert!(map.seal(&mut || Ok(None)).unwrap());
        assert!(map.is_verified(5));
        map.set_ready_and_clear_pending(chunk(3).as_base()).unwrap();
        assert!(map.seal(&mut || Ok(Some(9))).unwrap());
        assert!(map.is_verified(9));
    }

    /// A map another boot left unsealed forgets its ready chunks and verified record and
    /// rechecks until it is complete; one sealed, or unsealed by this boot, keeps them.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_a_map_unsealed_by_another_boot_is_reset() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-boot");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let chunk = |index| MockChunkInfo {
            index,
            ..Default::default()
        };
        let fill = |boot| {
            let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
            map.adopt_boot(boot, true).unwrap();
            // As a fill starts, even of chunks already ready.
            map.mark_unsealed().unwrap();
            for idx in 0..4 {
                map.set_ready_and_clear_pending(chunk(idx).as_base())
                    .unwrap();
            }
            map.set_verified(Some(7)).unwrap();
            map
        };

        // Sealed: kept in any boot.
        assert!(fill(1).seal(&mut || Ok(None)).unwrap());
        let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
        assert!(!map.adopt_boot(2, true).unwrap());
        assert!(map.is_range_all_ready() && map.is_verified(7));
        assert!(!map.is_rechecking());
        drop(map);

        // Unsealed by this boot, as after a kill: the page cache still holds the data.
        drop(fill(2));
        let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
        assert!(!map.adopt_boot(2, true).unwrap());
        assert!(map.is_range_all_ready() && map.is_verified(7));
        drop(map);

        // Unsealed by another boot.
        let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
        assert!(map.adopt_boot(3, true).unwrap());
        assert!(map.is_rechecking());
        assert!(!map.is_verified(7));
        for idx in 0..4 {
            assert!(!map.is_ready(chunk(idx).as_base()).unwrap());
        }
        drop(map);
        // Persisted, and the first ready bit claims the map for this boot.
        let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
        assert!(map.adopt_boot(3, true).unwrap());
        assert!(map.is_rechecking());
        for idx in 0..3 {
            map.set_ready_and_clear_pending(chunk(idx).as_base())
                .unwrap();
        }
        assert_eq!(unsealed_boot_on_disk(&blob_path), 3);
        assert!(map.is_rechecking());
        map.set_ready_and_clear_pending(chunk(3).as_base()).unwrap();
        assert!(!map.is_rechecking(), "complete, nothing left to recheck");
        drop(map);
        let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
        assert!(!map.adopt_boot(3, true).unwrap());
        assert!(map.is_range_all_ready() && !map.is_rechecking());
    }

    /// No ready bit is set between a seal's flush and its clearing the mark, even through
    /// another map of the same file: a fill racing a seal waits, then records the boot again.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_a_ready_bit_waits_for_a_seal() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-race");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let map = IndexedChunkMap::new(&blob_path, 8, true).unwrap();
        let other = std::sync::Arc::new(IndexedChunkMap::new(&blob_path, 8, true).unwrap());
        map.adopt_boot(7, true).unwrap();
        other.adopt_boot(7, true).unwrap();
        map.mark_unsealed().unwrap();

        let mut filler = None;
        assert!(
            map.seal(&mut || {
                let racing = other.clone();
                filler = Some(std::thread::spawn(move || {
                    let chunk = MockChunkInfo {
                        index: 1,
                        ..Default::default()
                    };
                    racing.set_ready_and_clear_pending(chunk.as_base()).unwrap();
                }));
                // Wait until the filler is at the seal lock, which this seal holds.
                while other.map.seal.arrived.load(Ordering::Acquire) == 0 {
                    std::thread::yield_now();
                }
                assert!(!other.map.is_chunk_ready(1).0, "a bit was set mid-seal");
                Ok(None)
            })
            .unwrap()
        );
        filler.unwrap().join().unwrap();
        assert!(other.map.is_chunk_ready(1).0);
        assert_eq!(unsealed_boot_on_disk(&blob_path), 7);
    }

    /// A mark whose flush failed is not taken as durable: the fill fails, and the next ready
    /// bit flushes the mark again before it is set.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_a_failed_mark_flush_is_retried() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-flush");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let chunk = |index| MockChunkInfo {
            index,
            ..Default::default()
        };
        let map = IndexedChunkMap::new(&blob_path, 8, true).unwrap();
        map.adopt_boot(7, true).unwrap();
        map.map.fail_next_flush.store(true, Ordering::Release);
        assert!(map.set_ready_and_clear_pending(chunk(0).as_base()).is_err());
        assert!(!map.is_ready(chunk(0).as_base()).unwrap());
        // The word is in the mapping, but not known to be on disk: the next bit flushes it.
        map.map.fail_next_flush.store(true, Ordering::Release);
        assert!(map.set_ready_and_clear_pending(chunk(1).as_base()).is_err());
        assert!(!map.is_ready(chunk(1).as_base()).unwrap());
        map.set_ready_and_clear_pending(chunk(1).as_base()).unwrap();
        assert_eq!(unsealed_boot_on_disk(&blob_path), 7);
        // Once durable, later bits need no flush.
        map.map.fail_next_flush.store(true, Ordering::Release);
        map.set_ready_and_clear_pending(chunk(2).as_base()).unwrap();
    }

    /// A map no release tracking boots created (an older release's) forgets its ready chunks
    /// once, for a fanotify opener; any opener records its boot before a ready bit.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_an_untracked_map_is_rechecked_once() {
        use std::os::unix::fs::FileExt;

        let dir = TempDir::new().unwrap();
        let blob_path = dir.path().join("blob-untracked");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let chunk = |index| MockChunkInfo {
            index,
            ..Default::default()
        };
        let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
        // Not forgetting: a non-fanotify opener keeps the bits but marks before its own.
        assert!(!map.adopt_boot(5, false).unwrap());
        map.set_ready_and_clear_pending(chunk(0).as_base()).unwrap();
        assert_eq!(unsealed_boot_on_disk(&blob_path), 5);
        assert!(map.seal(&mut || Ok(None)).unwrap());
        drop(map);
        // What an older release leaves: sealed-looking, never tracked.
        std::fs::OpenOptions::new()
            .write(true)
            .open(format!("{blob_path}.chunk_map"))
            .unwrap()
            .write_all_at(
                &0u64.to_ne_bytes(),
                std::mem::offset_of!(Header, tracked) as u64,
            )
            .unwrap();

        let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
        assert!(!map.adopt_boot(5, false).unwrap());
        assert!(map.is_ready(chunk(0).as_base()).unwrap());
        drop(map);
        let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
        assert!(map.adopt_boot(5, true).unwrap());
        assert!(!map.is_ready(chunk(0).as_base()).unwrap());
        assert!(map.is_rechecking());
        drop(map);
        let map = IndexedChunkMap::new(&blob_path, 4, true).unwrap();
        assert!(!map.adopt_boot(5, true).unwrap(), "rechecked only once");
    }
}
