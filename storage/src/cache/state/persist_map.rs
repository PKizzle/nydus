// Copyright 2021 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

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
pub(crate) const HEADER_RESERVED_SIZE: usize = HEADER_SIZE - 56;

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
    /// Zero when every ready bit is backed by data on stable storage: the map is sealed, or no
    /// release that tracks it has filled the cache. Otherwise the [boot_id](crate::utils::boot_id)
    /// of the boot in which a fill marked chunks ready since the last seal. Set and flushed
    /// before such a fill's first ready bit, so a map found marked by another boot may claim
    /// data lost with that boot's page cache. Zero in maps written before the field existed.
    pub unsealed_boot: u64,
    /// Non-zero while chunks the map forgot after a crash may still be in the data file: a fill
    /// first checks the bytes there against the chunk's digest. Cleared once every chunk is
    /// ready.
    pub recheck: u64,
    /// [MAGIC_TRACKED] once `unsealed_boot` covers every ready bit: in a map created by a release
    /// that tracks boots, or reset and rechecked by one. A map without it was filled by an older
    /// release, whose ready bits a zero `unsealed_boot` does not vouch for.
    pub tracked: u64,
    pub reserved: [u8; HEADER_RESERVED_SIZE],
}

/// `Header::tracked` value.
pub(crate) const MAGIC_TRACKED: u64 = 0x5452_4143_4b45_4421;

// SAFETY: `Header` is `#[repr(C)]` with six `u32`s and four `u64`s at 8-byte offsets followed by a byte array, so it has no padding,
// no interior mutability, and every bit pattern is valid.
unsafe impl FromMapped for Header {}

const _: () = assert!(size_of::<Header>() == HEADER_SIZE);

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

/// Get the 8-byte header word at `offset` in a chunk map mapping as an atomic.
fn atomic_header_u64(filemap: &FileMapState, offset: usize) -> StorageResult<&AtomicU64> {
    let ptr = filemap
        .validate_range(offset, size_of::<u64>())
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

/// What orders ready bits against [PersistMap::seal] for one map file, shared by every map of
/// that file in this process. Two processes filling the same map concurrently are not
/// supported: nothing orders one's seal against the other's ready bits.
#[derive(Default)]
pub(crate) struct SealState {
    /// Held shared from a fill finding the map marked to its ready bit, exclusively by a seal.
    lock: RwLock<()>,
    /// The boot whose mark in [Header::unsealed_boot] was flushed successfully and not
    /// cleared by a seal since; zero if none. The header word alone can hold a mark whose
    /// flush failed.
    durable: AtomicU64,
    /// The number of chunks whose ready bit is clear. Shared by every opener because each one
    /// sets and clears bits the others see; counted from the bitmap by the open that creates it.
    not_ready: AtomicU32,
    /// Fills that reached `lock`, for tests to know one is waiting.
    #[cfg(test)]
    pub(crate) arrived: std::sync::atomic::AtomicUsize,
}

/// The state of `file`, with `not_ready` as its count if no other map of the file is open or
/// `fresh` says the open rewrote the whole file.
fn seal_state_of(file: &File, not_ready: u32, fresh: bool) -> io::Result<Arc<SealState>> {
    use std::os::unix::fs::MetadataExt;
    type States = BTreeMap<(u64, u64), Weak<SealState>>;
    static STATES: Mutex<States> = Mutex::new(BTreeMap::new());

    let md = file.metadata()?;
    let mut states = STATES.lock().unwrap_or_else(|e| e.into_inner());
    states.retain(|_, state| state.strong_count() > 0);
    let key = (md.dev(), md.ino());
    let (state, fresh) = match states.get(&key).and_then(Weak::upgrade) {
        Some(state) => (state, fresh),
        None => (Arc::default(), true),
    };
    if fresh {
        state.not_ready.store(not_ready, Ordering::Release);
    }
    states.insert(key, Arc::downgrade(&state));
    Ok(state)
}

pub(crate) struct PersistMap {
    pub count: u32,
    filemap: FileMapState,
    /// The boot recorded in [Header::unsealed_boot] before a ready bit is set; zero until the
    /// opener names one.
    boot: AtomicU64,
    pub(crate) seal: Arc<SealState>,
    /// Makes the next map flush fail, as a full or failing disk would.
    #[cfg(test)]
    pub(crate) fail_next_flush: std::sync::atomic::AtomicBool,
}

impl PersistMap {
    pub fn open(
        filename: &str,
        chunk_count: u32,
        create: bool,
        persist: bool,
    ) -> StorageResult<Self> {
        Self::open_or_replace(filename, chunk_count, create, persist, true)
    }

    /// Open the map, replacing one found damaged with an empty map when `create` and
    /// `may_replace` allow it.
    fn open_or_replace(
        filename: &str,
        chunk_count: u32,
        create: bool,
        persist: bool,
        may_replace: bool,
    ) -> StorageResult<Self> {
        let damaged = |file: &File, reason: &str| -> StorageResult<Self> {
            if !(create && may_replace) {
                return Err(StorageError::InvalidData(format!(
                    "chunk map file {filename:?}: {reason}"
                )));
            }
            Self::replace(filename, file, reason)?;
            Self::open_or_replace(filename, chunk_count, create, persist, false)
        };

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
            // Not replaced like a damaged header: a live opener with another chunk count may
            // still use this map, and two maps over one data file would disagree about which of
            // its chunks are present.
            return Err(StorageError::InvalidData(format!(
                "chunk map file {filename:?}: size {file_size}, expected {expected_size}"
            )));
        }
        if create {
            Self::reserve(&file, expected_size, new_content)?;
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
                    drop(filemap);
                    return damaged(&file, "bad magic");
                }
            }

            new_content = true;
            Self::write_header(&mut file, expected_size)?;
        }

        // SAFETY: as above: the previous header reference is dead, and the header is not written by
        // anyone else while this process holds the file lock.
        let header = unsafe { filemap.get_mut::<Header>(0) }
            .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
        let (version, all_ready) = (header.version, header.all_ready);
        if version >= 1 && header.magic2 != MAGIC2 {
            drop(filemap);
            return damaged(&file, "bad second magic");
        }
        // The bitmap is what readiness checks read, so the count comes from it whatever the
        // header claims. Bits past the last chunk are not chunks.
        let mut ready_count = 0;
        for idx in 0..bitmap_size as usize {
            let byte = atomic_byte(&filemap, HEADER_SIZE + idx)
                .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?;
            let chunks = chunk_count as usize - idx * 8;
            let mask = if chunks >= 8 { 0xff } else { !(0xff >> chunks) };
            ready_count += (byte.load(Ordering::Acquire) & mask).count_ones();
        }
        let ready = ready_count == chunk_count;
        if version >= 1 && (all_ready == MAGIC_ALL_READY) != ready {
            // Older releases trust this marker over the bitmap, so it must not claim a chunk
            // that is not ready.
            atomic_all_ready(&filemap)
                .map_err(|e| StorageError::cache_io("reach the chunk map contents", e))?
                .store(if ready { MAGIC_ALL_READY } else { 0 }, Ordering::Release);
            let _ = file.sync_all();
        }
        // Looked up while the file lock is held, so the count of an opener already filling the
        // map is kept instead of this bitmap count, which its fills may have overtaken.
        let seal = seal_state_of(&file, chunk_count - ready_count, new_content)
            .map_err(|e| StorageError::cache_io("stat the chunk map file", e))?;

        // The mapping holds a duplicate of `file`, which shares the lock, so release it explicitly.
        file.unlock()
            .map_err(|e| StorageError::cache_io("unlock the chunk map file", e))?;

        readahead(file.as_raw_fd(), 0, expected_size);
        if !persist {
            let _ = std::fs::remove_file(filename);
        }

        Ok(Self {
            count: chunk_count,
            filemap,
            boot: AtomicU64::new(0),
            seal,
            #[cfg(test)]
            fail_next_flush: Default::default(),
        })
    }

    /// Unlink the damaged map `file` at `filename`, held under its exclusive lock, so the next
    /// open creates an empty one. The map holds only readiness: losing it costs refetches, and
    /// the data file is left alone. Unlinking rather than truncating keeps the old file intact
    /// for any process that still maps it, which would fault on a truncated mapping.
    fn replace(filename: &str, file: &File, reason: &str) -> StorageResult<()> {
        use std::os::unix::fs::MetadataExt;

        let held = file
            .metadata()
            .map_err(|e| StorageError::cache_io("stat the chunk map file", e))?;
        // Another opener that found the same damage may have replaced the file already.
        match std::fs::metadata(filename) {
            Ok(m) if m.dev() == held.dev() && m.ino() == held.ino() => {}
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(StorageError::cache_io("stat the chunk map file", e)),
        }
        warn!("chunk map file {filename:?} is damaged ({reason}), replacing it with an empty one");
        match std::fs::remove_file(filename) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(StorageError::cache_io(
                "remove the damaged chunk map file",
                e,
            )),
            _ => Ok(()),
        }
    }

    /// Allocate every block of the map, held under its exclusive lock. The bitmap is written
    /// through a shared mapping, and a store into a hole on a full file system raises SIGBUS,
    /// which kills the whole process; reserving the blocks here turns that into an error
    /// (ENOSPC) from the open instead. Maps left sparse by older releases are reserved too.
    fn reserve(file: &File, size: u64, new: bool) -> StorageResult<()> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: a plain syscall on an open descriptor; mode 0 only allocates blocks and
            // the file already has this size, so its contents do not change.
            if unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, size as libc::off_t) } == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EOPNOTSUPP) {
                return Err(StorageError::cache_io("reserve the chunk map blocks", err));
            }
        }
        // Without fallocate, writing zeros allocates the blocks of a new map. An existing map's
        // bitmap is live state that other openers may be changing, so it stays as it is.
        if new {
            use std::os::unix::fs::FileExt;
            let bitmap = vec![0u8; (size - HEADER_SIZE as u64) as usize];
            file.write_all_at(&bitmap, HEADER_SIZE as u64)
                .and_then(|()| file.sync_all())
                .map_err(|e| StorageError::cache_io("reserve the chunk map blocks", e))?;
        }
        Ok(())
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
            unsealed_boot: 0,
            recheck: 0,
            // A new map has no ready bit an older release set.
            tracked: MAGIC_TRACKED,
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
        if self.is_chunk_ready(index).0 {
            return Ok(());
        }
        // Held until the bit is set, so a seal cannot clear the mark in between.
        #[cfg(test)]
        self.seal.arrived.fetch_add(1, Ordering::AcqRel);
        let _fill = self.seal.lock.read().unwrap_or_else(|e| e.into_inner());
        self.mark_unsealed_locked()?;

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
                // Flush the map once its last chunk is ready; nothing is left to recheck.
                let not_ready = &self.seal.not_ready;
                if not_ready.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                    == Ok(1)
                {
                    if let Ok(w) = self.recheck_word() {
                        w.store(0, Ordering::Release);
                    }
                    if let Err(e) = self.filemap.sync_data() {
                        warn!("failed to flush the completed chunk map: {e}");
                    }
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
        if byte.fetch_and(!mask, Ordering::AcqRel) & mask != 0 {
            self.ready_count_word()?.fetch_sub(1, Ordering::AcqRel);
            let count = self.count;
            let _ = (self.seal.not_ready).fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < count).then_some(n + 1)
            });
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

    pub fn not_ready_count(&self) -> u32 {
        self.seal.not_ready.load(Ordering::Acquire)
    }

    pub fn ready_chunks(&self) -> u32 {
        self.count - self.not_ready_count()
    }

    fn data_stamp_word(&self) -> StorageResult<&AtomicU64> {
        atomic_header_u64(&self.filemap, std::mem::offset_of!(Header, data_stamp))
    }

    fn unsealed_boot_word(&self) -> StorageResult<&AtomicU64> {
        atomic_header_u64(&self.filemap, std::mem::offset_of!(Header, unsealed_boot))
    }

    fn recheck_word(&self) -> StorageResult<&AtomicU64> {
        atomic_header_u64(&self.filemap, std::mem::offset_of!(Header, recheck))
    }

    fn tracked_word(&self) -> StorageResult<&AtomicU64> {
        atomic_header_u64(&self.filemap, std::mem::offset_of!(Header, tracked))
    }

    /// Track boots for this map from now on, as boot `boot`: every ready bit is preceded by a
    /// flushed mark. With `forget_untrusted`, a map whose ready bits are not known to be on
    /// stable storage (left unsealed by another boot, or never tracked: filled by an older
    /// release) has its ready bits and verified record cleared and [Self::is_rechecking]
    /// turned on, keeping the data file for the fills to check. Returns whether that happened.
    pub fn adopt_boot(&self, boot: u64, forget_untrusted: bool) -> StorageResult<bool> {
        let mut forget = false;
        if forget_untrusted {
            let unsealed = self.unsealed_boot_word()?.load(Ordering::Acquire);
            let tracked = self.tracked_word()?;
            forget = (unsealed != 0 && unsealed != boot)
                || tracked.load(Ordering::Acquire) != MAGIC_TRACKED;
            if forget {
                self.recheck_word()?.store(1, Ordering::Release);
                self.reset()?;
                self.set_verified(None)?;
                tracked.store(MAGIC_TRACKED, Ordering::Release);
                self.flush()?;
            }
        }
        self.boot.store(boot, Ordering::Release);
        Ok(forget)
    }

    fn flush(&self) -> StorageResult<()> {
        #[cfg(test)]
        if self.fail_next_flush.swap(false, Ordering::AcqRel) {
            return Err(StorageError::cache_io(
                "flush the chunk map",
                io::Error::from_raw_os_error(libc::EIO),
            ));
        }
        self.filemap
            .sync_data()
            .map_err(|e| StorageError::cache_io("flush the chunk map", e))
    }

    /// Record the tracked boot in the header and flush it, unless a flush in this process
    /// already made it durable. Takes no lock: callers setting a ready bit next hold the seal
    /// lock across both.
    fn mark_unsealed_locked(&self) -> StorageResult<()> {
        let boot = self.boot.load(Ordering::Acquire);
        if boot == 0 {
            return Ok(());
        }
        let word = self.unsealed_boot_word()?;
        if word.load(Ordering::Acquire) == boot && self.seal.durable.load(Ordering::Acquire) == boot
        {
            return Ok(());
        }
        word.store(boot, Ordering::Release);
        self.flush()?;
        self.seal.durable.store(boot, Ordering::Release);
        Ok(())
    }

    /// Record the tracked boot as filling the map, flushed before returning. Every ready bit
    /// does this too; a fill calls it first to fail before fetching anything.
    pub fn mark_unsealed(&self) -> StorageResult<()> {
        let _fill = self.seal.lock.read().unwrap_or_else(|e| e.into_inner());
        self.mark_unsealed_locked()
    }

    /// Seal the map: record that every ready bit is backed by data on stable storage. With no
    /// ready bit set in between, `flush` makes the data file durable and returns its current
    /// stamp when this opener's own writes account for its change time. That stamp replaces
    /// the recorded one only if the map is verified and its ready count is current. Returns
    /// whether the map was unsealed; an error leaves it unsealed.
    pub fn seal(
        &self,
        flush: &mut dyn FnMut() -> StorageResult<Option<u64>>,
    ) -> StorageResult<bool> {
        let _sealing = self.seal.lock.write().unwrap_or_else(|e| e.into_inner());
        let word = self.unsealed_boot_word()?;
        if word.load(Ordering::Acquire) == 0 {
            return Ok(false);
        }
        // From here the mark may be cleared, so the next ready bit flushes it again.
        self.seal.durable.store(0, Ordering::Release);
        if let Some(stamp) = flush()?
            && self.verified_word()?.load(Ordering::Acquire) == MAGIC_VERIFIED
            && self.ready_count_word()?.load(Ordering::Acquire) == self.ready_chunks()
        {
            self.update_data_stamp(stamp)?;
        }
        word.store(0, Ordering::Release);
        self.flush()?;
        Ok(true)
    }

    /// Whether a fill checks the bytes already in the data file before fetching a chunk.
    pub fn is_rechecking(&self) -> bool {
        self.recheck_word()
            .is_ok_and(|w| w.load(Ordering::Acquire) != 0)
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
        self.not_ready_count() == 0
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
        self.seal.not_ready.store(self.count, Ordering::Release);
        self.ready_count_word()?.store(0, Ordering::Release);

        // Persist before returning: if the process dies between the punch and a later flush,
        // a stale on-disk bitmap would claim the discarded chunks are present.
        self.filemap
            .sync_data()
            .map_err(|e| StorageError::cache_io("flush the chunk map", e))?;

        Ok(())
    }
}

/// Open the chunk map file at `path` for `chunk_count` chunks, whatever it holds, and drive it
/// with `ops` the way fills, invalidations, seals and restarts do, checking that the in-memory
/// not-ready count matches the bitmap. Entry point for the `chunk_map` fuzz target.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_chunk_map(path: &str, chunk_count: u32, ops: &[u8]) {
    let open = || PersistMap::open(path, chunk_count, true, true);
    let Ok(mut map) = open() else {
        return;
    };
    let mut ops = ops.iter().copied();
    while let Some(op) = ops.next() {
        // Indices past the bitmap test `validate_index`.
        let arg = u16::from_le_bytes([ops.next().unwrap_or(0), ops.next().unwrap_or(0)]);
        let index = arg as u32 % (chunk_count + 8);
        match op % 10 {
            0 => {
                let _ = map.set_chunk_ready(index);
            }
            1 => {
                let _ = map.clear_chunk_ready(index);
            }
            2 => {
                let _ = map.adopt_boot(1 + (arg % 3) as u64, arg & 0x100 != 0);
            }
            3 => {
                let _ = map.mark_unsealed();
            }
            4 => {
                let stamp = (arg & 1 != 0).then_some(arg as u64);
                let _ = map.seal(&mut || Ok(stamp));
            }
            5 => {
                let _ = map.set_verified((arg & 1 != 0).then_some(arg as u64));
                let _ = map.is_verified(arg as u64);
            }
            6 => {
                let _ = map.reset();
            }
            7 => {
                if map.validate_index(index).is_ok() {
                    let _ = map.is_chunk_ready(index);
                }
                let _ = map.is_rechecking();
            }
            8 => {
                // A second opener of the same file in this process, sharing its seal state.
                if let Ok(other) = PersistMap::open(path, chunk_count, true, true) {
                    let _ = other.adopt_boot(1 + (arg % 3) as u64, false);
                    let _ = other.mark_unsealed();
                    if arg & 0x200 != 0 {
                        let _ = other.set_chunk_ready(index);
                    } else {
                        let _ = other.clear_chunk_ready(index);
                    }
                    let _ = other.seal(&mut || Ok(None));
                    assert_eq!(other.not_ready_count(), map.not_ready_count());
                }
            }
            _ => {
                // A restart: the next opener parses what this one left behind.
                drop(map);
                let Ok(reopened) = open() else {
                    return;
                };
                map = reopened;
            }
        }
        let not_ready = (0..chunk_count)
            .filter(|&idx| !map.is_chunk_ready(idx).0)
            .count() as u32;
        assert_eq!(map.not_ready_count(), not_ready, "out of {chunk_count}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Write a map for `chunk_count` chunks with the given header words and bitmap, and open it.
    fn open_raw(
        dir: &TempDir,
        chunk_count: u32,
        version: u32,
        all_ready: u32,
        bitmap: &[u8],
    ) -> (String, PersistMap) {
        let path = dir.path().join("blob.chunk_map");
        let path = path.to_str().unwrap().to_string();
        let mut content = vec![0u8; HEADER_SIZE];
        content[0..4].copy_from_slice(&MAGIC1.to_le_bytes());
        content[4..8].copy_from_slice(&version.to_le_bytes());
        content[8..12].copy_from_slice(&MAGIC2.to_le_bytes());
        content[12..16].copy_from_slice(&all_ready.to_le_bytes());
        content.extend_from_slice(bitmap);
        assert_eq!(
            content.len(),
            HEADER_SIZE + chunk_count.div_ceil(8) as usize
        );
        std::fs::write(&path, content).unwrap();
        let map = PersistMap::open(&path, chunk_count, true, true).unwrap();
        (path, map)
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_v0_map_counts_its_ready_bits() {
        let dir = TempDir::new().unwrap();
        let mut bitmap = [0u8; 6];
        bitmap[0] = 0x80;
        let (_, map) = open_raw(&dir, 41, 0, 0, &bitmap);
        assert_eq!(map.ready_chunks(), 1);
        map.clear_chunk_ready(0).unwrap();
        assert_eq!(map.not_ready_count(), 41);
        assert_eq!(map.ready_chunks(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_all_ready_header_over_a_clear_bit() {
        let dir = TempDir::new().unwrap();
        let (path, map) = open_raw(&dir, 8, 1, MAGIC_ALL_READY, &[0x7f]);
        assert!(!map.is_range_all_ready());
        assert!(!map.is_chunk_ready(0).0);
        map.set_chunk_ready(0).unwrap();
        assert_eq!(map.not_ready_count(), 0);
        assert!(map.is_range_all_ready());
        drop(map);
        assert!(
            PersistMap::open(&path, 8, true, true)
                .unwrap()
                .is_range_all_ready()
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_padding_bits_are_not_chunks() {
        let dir = TempDir::new().unwrap();
        // Chunk 0 is not ready; the last byte holds chunk 40 and seven padding bits.
        let bitmap = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff];
        let (_, map) = open_raw(&dir, 41, 1, 0, &bitmap);
        assert_eq!(map.not_ready_count(), 1);
        assert!(!map.is_range_all_ready());
        map.set_chunk_ready(0).unwrap();
        assert!(map.is_range_all_ready());
        map.clear_chunk_ready(40).unwrap();
        assert_eq!(map.not_ready_count(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_second_opener_shares_the_count() {
        let dir = TempDir::new().unwrap();
        let (path, first) = open_raw(&dir, 8, 1, 0, &[0]);
        let second = PersistMap::open(&path, 8, true, true).unwrap();
        first.set_chunk_ready(3).unwrap();
        assert_eq!(second.ready_chunks(), 1);
        second.clear_chunk_ready(3).unwrap();
        assert_eq!(first.not_ready_count(), 8);
        assert_eq!(second.not_ready_count(), 8);
        for idx in 0..8 {
            second.set_chunk_ready(idx).unwrap();
        }
        assert!(first.is_range_all_ready());
        first.reset().unwrap();
        assert_eq!(second.not_ready_count(), 8);
    }
}
