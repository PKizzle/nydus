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
    use vmm_sys_util::tempdir::TempDir;

    use super::super::persist_map::*;
    use super::*;
    use crate::device::v5::BlobV5ChunkInfo;
    use crate::test::MockChunkInfo;

    #[test]
    fn test_indexed_new_invalid_file_size() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
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
    fn test_indexed_new_zero_file_size() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
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
    fn test_indexed_new_header_not_ready() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
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
    fn test_indexed_new_all_ready() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
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
    fn test_indexed_new_load_v0() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
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
    fn test_reset_revokes_every_chunk() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-reset");
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
    fn test_reset_survives_reopen() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-reset-persist");
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
}
