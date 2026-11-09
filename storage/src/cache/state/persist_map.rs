// Copyright 2021 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use nydus_utils::div_round_up;
use nydus_utils::filemap::{FileMapState, FromMapped, clone_file};

use crate::utils::readahead;
use crate::{StorageError, StorageResult};

pub(crate) const MAGIC1: u32 = 0x424D_4150;
pub(crate) const MAGIC2: u32 = 0x434D_4150;
pub(crate) const MAGIC_ALL_READY: u32 = 0x4D4D_4150;
/// `Header::verified` value: every chunk marked ready has been checked against its digest.
pub(crate) const MAGIC_VERIFIED: u32 = 0x5644_4150;
pub(crate) const HEADER_SIZE: usize = 4096;
pub(crate) const HEADER_RESERVED_SIZE: usize = HEADER_SIZE - 32;

/// The blob chunk map file header, 4096 bytes.
#[repr(C)]
pub(crate) struct Header {
    /// PersistMap magic number
    pub magic: u32,
    pub version: u32,
    pub magic2: u32,
    pub all_ready: u32,
    /// [MAGIC_VERIFIED] once every ready chunk has been checked against its digest. Openers that
    /// fill without validating clear it. Zero in maps written before the field existed.
    pub verified: u32,
    /// The number of ready chunks, kept by every ready-bit change this version makes.
    /// `verified` holds only while it matches the bitmap: a release that predates the field
    /// leaves it alone while it fills chunks without validating them, which the mismatch then
    /// reveals.
    pub ready_count: u32,
    /// A stamp of the data file's change time and size, kept by every write this version makes
    /// to it. `verified` holds only while it matches: a release that predates the field cannot
    /// write the data file, not even to invalidate and refill it, without changing its ctime.
    pub data_stamp: u64,
    pub reserved: [u8; HEADER_RESERVED_SIZE],
}

// SAFETY: `Header` is `#[repr(C)]` with six `u32`s and a `u64` at an 8-byte offset followed by a byte array, so it has no padding,
// no interior mutability, and every bit pattern is valid.
unsafe impl FromMapped for Header {}

impl Header {
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `Header` has no padding (see the `FromMapped` impl), so all `size_of::<Header>()`
        // bytes of `self` are initialized; the slice borrows `self`.
        unsafe {
            std::slice::from_raw_parts(
                self as *const Header as *const u8,
                std::mem::size_of::<Header>(),
            )
        }
    }
}

/// Get the byte at `offset` in a chunk map mapping as an atomic.
fn atomic_byte(filemap: &FileMapState, offset: usize) -> io::Result<&AtomicU8> {
    let ptr = filemap.validate_range(offset, 1)?;
    // SAFETY: the byte is in the writable mapping, which outlives the reference. The bitmap is only
    // ever accessed atomically, and the header is only read this way before it's written.
    Ok(unsafe { AtomicU8::from_ptr(ptr.cast_mut()) })
}

/// Get the header's `all_ready` word in a chunk map mapping as an atomic.
fn atomic_all_ready(filemap: &FileMapState) -> io::Result<&AtomicU32> {
    atomic_header_word(filemap, std::mem::offset_of!(Header, all_ready))
}

/// Get the header word at `offset` in a chunk map mapping as an atomic.
fn atomic_header_word(filemap: &FileMapState, offset: usize) -> io::Result<&AtomicU32> {
    let ptr = filemap
        .validate_range(offset, size_of::<u32>())?
        .cast::<u32>();
    if !ptr.is_aligned() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unaligned chunk map header",
        ));
    }
    // SAFETY: the word is aligned and in the writable mapping, which outlives the reference, and
    // once the map is open the word is only accessed atomically.
    Ok(unsafe { AtomicU32::from_ptr(ptr.cast_mut()) })
}

pub(crate) struct PersistMap {
    pub count: u32,
    pub not_ready_count: AtomicU32,
    filemap: FileMapState,
}

impl PersistMap {
    pub fn open(
        filename: &str,
        chunk_count: u32,
        create: bool,
        persist: bool,
    ) -> StorageResult<Self> {
        if chunk_count == 0 {
            return Err(StorageError::InvalidArgument(
                "chunk count should be greater than 0".to_string(),
            ));
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(create)
            .create(create)
            .truncate(!persist)
            .open(filename)
            .map_err(|err| StorageError::cache_io("open the chunk map file", err))?;
        // Other processes sharing the cache directory may open the same file, so initialize and
        // check it under a file lock. Outside the lock only the bitmap changes, through atomic
        // operations.
        if create {
            file.lock()
        } else {
            file.lock_shared()
        }
        .map_err(|e| StorageError::cache_io("lock the chunk map file", e))?;

        let file_size = file
            .metadata()
            .map_err(|e| StorageError::cache_io("stat the chunk map file", e))?
            .len();
        let bitmap_size = div_round_up(chunk_count as u64, 8u64);
        let expected_size = HEADER_SIZE as u64 + bitmap_size;
        let mut new_content = false;

        if file_size == 0 {
            if !create {
                return Err(StorageError::InvalidState(
                    "chunk map file does not exist and may not be created".to_string(),
                ));
            }

            new_content = true;
            Self::write_header(&mut file, expected_size)?;
        } else if file_size != expected_size {
            // File size doesn't match, it's too risky to accept the chunk state file. Fallback to
            // always mark chunk data as not ready.
            warn!("blob chunk_map file may be corrupted: {:?}", filename);
            return Err(StorageError::InvalidData(format!(
                "chunk_map file {:?} is invalid",
                filename
            )));
        }

        let file2 = clone_file(file.as_raw_fd())
            .map_err(|e| StorageError::cache_io("dup the chunk map fd", e))?;
        // SAFETY: the header is written through `file` only under the exclusive file lock, while no
        // reference into the mapping is alive, and the bitmap is accessed only through atomic
        // operations.
        let mut filemap = unsafe { FileMapState::new(file2, 0, expected_size as usize, true) }
            .map_err(|e| StorageError::cache_io("mmap the chunk map file", e))?;
        // SAFETY: the reference ends before `write_header` writes the file below. Another opener
        // holding the shared lock may read the header concurrently, but nothing writes it while
        // this process holds the file lock and the reference.
        let header = unsafe { filemap.get_mut::<Header>(0) }
            .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
        if header.magic != MAGIC1 {
            if !create {
                return Err(StorageError::InvalidState(
                    "chunk map file does not exist and may not be created".to_string(),
                ));
            }

            // A process that stopped between "file.set_len()" and "file.write(&header)" leaves a
            // file whose content is all zero. Detect that and write out the header again.
            for idx in 0..expected_size as usize {
                let byte = atomic_byte(&filemap, idx)
                    .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
                if byte.load(Ordering::Acquire) != 0 {
                    return Err(StorageError::InvalidData(format!(
                        "invalid blob chunk_map file header: {:?}",
                        filename
                    )));
                }
            }

            new_content = true;
            Self::write_header(&mut file, expected_size)?;
        }

        // SAFETY: as above: the previous header reference is dead, and the header is not written by
        // anyone else while this process holds the file lock.
        let header = unsafe { filemap.get_mut::<Header>(0) }
            .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
        let mut not_ready_count = chunk_count;
        if header.version >= 1 {
            if header.magic2 != MAGIC2 {
                return Err(StorageError::InvalidData(format!(
                    "invalid blob chunk_map file header: {:?}",
                    filename
                )));
            }
            if header.all_ready == MAGIC_ALL_READY {
                not_ready_count = 0;
            } else if new_content {
                not_ready_count = chunk_count;
            } else {
                let mut ready_count = 0;
                for idx in HEADER_SIZE..expected_size as usize {
                    let current = atomic_byte(&filemap, idx)
                        .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
                    let val = current.load(Ordering::Acquire);
                    ready_count += val.count_ones() as u32;
                }

                if ready_count >= chunk_count {
                    // SAFETY: NOT fully established. The file lock keeps other openers out of this
                    // function, but a process that already opened the map may `store` to
                    // `all_ready` atomically (see `invalidate`) while this plain `&mut` write runs;
                    // it relies on `all_ready` being set only once every chunk is ready, after
                    // which nothing clears it except invalidation.
                    let header = unsafe { filemap.get_mut::<Header>(0) }
                        .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
                    header.all_ready = MAGIC_ALL_READY;
                    let _ = file.sync_all();
                    not_ready_count = 0;
                } else {
                    not_ready_count = chunk_count - ready_count;
                }
            }
        }

        // The mapping holds a duplicate of `file`, which shares the lock, so release it explicitly.
        file.unlock()
            .map_err(|e| StorageError::cache_io("unlock the chunk map file", e))?;

        readahead(file.as_raw_fd(), 0, expected_size);
        if !persist {
            let _ = std::fs::remove_file(filename);
        }

        Ok(Self {
            count: chunk_count,
            not_ready_count: AtomicU32::new(not_ready_count),
            filemap,
        })
    }

    fn write_header(file: &mut File, size: u64) -> StorageResult<()> {
        let header = Header {
            magic: MAGIC1,
            version: 1,
            magic2: MAGIC2,
            all_ready: 0,
            verified: 0,
            ready_count: 0,
            data_stamp: 0,
            reserved: [0x0u8; HEADER_RESERVED_SIZE],
        };

        // Set file size to expected value and sync to disk.
        file.set_len(size)
            .map_err(|e| StorageError::cache_io("size the chunk map file", e))?;
        file.sync_all()
            .map_err(|e| StorageError::cache_io("flush the chunk map file", e))?;
        // write file header and sync to disk.
        file.write_all(header.as_slice())
            .map_err(|e| StorageError::cache_io("write the chunk map header", e))?;
        file.sync_all()
            .map_err(|e| StorageError::cache_io("flush the chunk map file", e))?;

        Ok(())
    }

    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.filemap.size()
    }

    #[inline]
    pub fn validate_index(&self, idx: u32) -> StorageResult<u32> {
        if idx < self.count {
            Ok(idx)
        } else {
            Err(StorageError::InvalidData(format!(
                "chunk index {} exceeds chunk count {}",
                idx, self.count
            )))
        }
    }

    #[inline]
    fn read_u8(&self, idx: u32) -> u8 {
        let start = HEADER_SIZE + (idx as usize >> 3);
        let current = atomic_byte(&self.filemap, start).unwrap();

        current.load(Ordering::Acquire)
    }

    #[inline]
    fn write_u8(&self, idx: u32, current: u8) -> bool {
        let mask = Self::index_to_mask(idx);
        let expected = current | mask;
        let start = HEADER_SIZE + (idx as usize >> 3);
        let atomic_value = atomic_byte(&self.filemap, start).unwrap();

        atomic_value
            .compare_exchange(current, expected, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    #[inline]
    fn index_to_mask(index: u32) -> u8 {
        let pos = 8 - ((index & 0b111) + 1);
        1 << pos
    }

    #[inline]
    pub fn is_chunk_ready(&self, index: u32) -> (bool, u8) {
        let mask = Self::index_to_mask(index);
        let current = self.read_u8(index);
        let ready = current & mask == mask;

        (ready, current)
    }

    pub fn set_chunk_ready(&self, index: u32) -> StorageResult<()> {
        let index = self.validate_index(index)?;

        // Loop to atomically update the state bit corresponding to the chunk index.
        loop {
            let (ready, current) = self.is_chunk_ready(index);
            if ready {
                break;
            }

            if self.write_u8(index, current) {
                if let Ok(w) = self.ready_count_word() {
                    w.fetch_add(1, Ordering::AcqRel);
                }
                // Flush the map once its last chunk is ready.
                if self.not_ready_count.fetch_sub(1, Ordering::AcqRel) == 1
                    && let Err(e) = self.filemap.sync_data()
                {
                    warn!("failed to flush the completed chunk map: {e}");
                }
                break;
            }
        }

        Ok(())
    }

    /// Clear one chunk's ready state, persisted before returning.
    pub fn clear_chunk_ready(&self, index: u32) -> StorageResult<()> {
        let index = self.validate_index(index)?;
        // The header marker short-circuits readiness checks, so it goes first.
        let all_ready = atomic_all_ready(&self.filemap)
            .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
        all_ready.store(0, Ordering::Release);
        let byte = atomic_byte(&self.filemap, HEADER_SIZE + (index as usize >> 3))
            .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
        let mask = Self::index_to_mask(index);
        // A count of zero claims every chunk ready whatever the bitmap says, so it must move too.
        let was_ready = byte.fetch_and(!mask, Ordering::AcqRel) & mask != 0;
        if was_ready {
            self.ready_count_word()?.fetch_sub(1, Ordering::AcqRel);
        }
        if was_ready || self.not_ready_count.load(Ordering::Acquire) == 0 {
            self.not_ready_count.fetch_add(1, Ordering::AcqRel);
        }
        self.filemap
            .sync_data()
            .map_err(|e| StorageError::cache_io("flush the chunk map", e))
    }

    fn verified_word(&self) -> StorageResult<&AtomicU32> {
        atomic_header_word(&self.filemap, std::mem::offset_of!(Header, verified))
            .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))
    }

    fn ready_count_word(&self) -> StorageResult<&AtomicU32> {
        atomic_header_word(&self.filemap, std::mem::offset_of!(Header, ready_count))
            .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))
    }

    pub fn ready_chunks(&self) -> u32 {
        self.count - self.not_ready_count.load(Ordering::Acquire)
    }

    fn data_stamp_word(&self) -> StorageResult<&AtomicU64> {
        let ptr = self
            .filemap
            .validate_range(std::mem::offset_of!(Header, data_stamp), size_of::<u64>())
            .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?
            .cast::<u64>();
        if !ptr.is_aligned() {
            return Err(StorageError::InvalidState(
                "unaligned chunk map header".to_string(),
            ));
        }
        // SAFETY: the word is aligned and in the writable mapping, which outlives the reference,
        // and once the map is open it is only accessed atomically.
        Ok(unsafe { AtomicU64::from_ptr(ptr.cast_mut()) })
    }

    /// Whether the header records every ready chunk as checked against its digest, and neither
    /// a ready bit nor the data file (`data_stamp`, see [Header::data_stamp]) has changed since
    /// but through this version, which validates every chunk it fills.
    pub fn is_verified(&self, data_stamp: u64) -> bool {
        self.verified_word()
            .is_ok_and(|w| w.load(Ordering::Acquire) == MAGIC_VERIFIED)
            && self
                .ready_count_word()
                .is_ok_and(|w| w.load(Ordering::Acquire) == self.ready_chunks())
            && self
                .data_stamp_word()
                .is_ok_and(|w| w.load(Ordering::Acquire) == data_stamp)
    }

    /// Record the data file's stamp after this version wrote it.
    pub fn update_data_stamp(&self, data_stamp: u64) -> StorageResult<()> {
        self.data_stamp_word()?.store(data_stamp, Ordering::Release);
        Ok(())
    }

    /// Record every ready chunk as checked against its digest with the data file at
    /// `data_stamp`, or with `None` that they are not, persisted before returning. A fill racing
    /// with this can leave the count or stamp stale, which reads as not verified: the safe
    /// direction.
    pub fn set_verified(&self, data_stamp: Option<u64>) -> StorageResult<()> {
        let verified = data_stamp.is_some();
        if let Some(stamp) = data_stamp {
            self.update_data_stamp(stamp)?;
            let word = self.ready_count_word()?;
            loop {
                let ready = self.ready_chunks();
                word.store(ready, Ordering::Release);
                if self.ready_chunks() == ready {
                    break;
                }
            }
        }
        let value = if verified { MAGIC_VERIFIED } else { 0 };
        if self.verified_word()?.swap(value, Ordering::AcqRel) != value {
            self.filemap
                .sync_data()
                .map_err(|e| StorageError::cache_io("flush the chunk map", e))?;
        }
        Ok(())
    }

    #[inline]
    pub fn is_range_all_ready(&self) -> bool {
        self.not_ready_count.load(Ordering::Acquire) == 0
    }

    /// Revoke every chunk's ready state, returning the map to "nothing cached".
    ///
    /// The inverse of the incremental [`set_chunk_ready`](Self::set_chunk_ready): clears the
    /// `all_ready` header marker and zeroes the whole bitmap, so subsequent reads miss and
    /// re-fetch.
    ///
    /// Callers invalidating a cache MUST do this *before* discarding the cached bytes. The
    /// bitmap is a promise that data is present; dropping the data first leaves a window in
    /// which the map still claims ready for a hole, and a reader in that window is served
    /// zeros. Clearing first only risks a redundant re-fetch, which is harmless.
    pub fn reset(&self) -> StorageResult<()> {
        let size = self.filemap.size();

        // Clear the header marker first: it short-circuits `is_range_all_ready`, so while the
        // bitmap is being zeroed a concurrent reader must not still see "all ready".
        //
        // Written through an `AtomicU32` rather than `get_mut::<Header>`, which needs `&mut
        // self` the `Arc<dyn ChunkMap>` this hangs off cannot provide. `atomic_all_ready` uses
        // `offset_of!` to keep the two views of the header from drifting apart.
        let all_ready = atomic_all_ready(&self.filemap)
            .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
        all_ready.store(0, Ordering::Release);

        for idx in HEADER_SIZE..size {
            let byte = atomic_byte(&self.filemap, idx)
                .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
            byte.store(0, Ordering::Release);
        }
        self.not_ready_count.store(self.count, Ordering::Release);
        self.ready_count_word()?.store(0, Ordering::Release);

        // Persist before returning: if the process dies between the punch and a later flush,
        // a stale on-disk bitmap would claim the discarded chunks are present.
        self.filemap
            .sync_data()
            .map_err(|e| StorageError::cache_io("flush the chunk map", e))?;

        Ok(())
    }
}
