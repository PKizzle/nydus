// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::ptr::NonNull;
use std::sync::Arc;

use nydus_api::MetadataSource;

use crate::with_context;

/// Types that can be read straight out of mapped file bytes.
///
/// # Safety
/// Every bit pattern of `size_of::<Self>()` bytes must be a valid `Self`, and `Self` must have no
/// padding and no interior mutability. That holds for integers, arrays of them, and `#[repr(C)]`
/// structs without gaps whose fields are plain integers, arrays, or structs of them.
pub unsafe trait FromMapped {}

// SAFETY: every bit pattern of a `u8` is valid and it has no padding or interior mutability.
unsafe impl FromMapped for u8 {}
// SAFETY: every bit pattern of a `u16` is valid and it has no padding or interior mutability.
unsafe impl FromMapped for u16 {}
// SAFETY: every bit pattern of a `u32` is valid and it has no padding or interior mutability.
unsafe impl FromMapped for u32 {}
// SAFETY: every bit pattern of a `u64` is valid and it has no padding or interior mutability.
unsafe impl FromMapped for u64 {}
// SAFETY: an array has no padding between elements, so it inherits the all-bit-patterns-valid,
// no-padding, no-interior-mutability guarantee from `T: FromMapped`.
unsafe impl<T: FromMapped, const N: usize> FromMapped for [T; N] {}

/// The bytes of a region of a file, held in memory.
///
/// The bytes either come from mapping the region with `mmap` ([`FileMapState::new`]) or from
/// copying it into a page-aligned buffer ([`FileMapState::read`]). Readers see the same API, page
/// alignment and bounds checks for both; which one to use is the caller's choice. A copy cannot
/// change underneath its readers, so it carries none of the mapping's safety contract, and it is
/// the only form Miri can check.
pub struct FileMapState {
    base: *const u8,
    size: usize,
    fd: RawFd,
    writable: bool,
    /// `base` is a heap buffer allocated with [`copy_layout`], not a mapping.
    copied: bool,
}

// SAFETY: the memory is process-wide (a mapping or a heap buffer) and `fd` is owned, so neither is
// tied to the creating thread. Shared access only reads, `new` requires that nothing writes the
// mapped range under live references, and mutable access needs `&mut self` plus the caller's
// `unsafe` contract.
unsafe impl Send for FileMapState {}
// SAFETY: `&FileMapState` only hands out shared references into memory that is unchanging while
// borrowed (a copy by construction, a mapping by `new`'s contract); see the `Send` impl above.
unsafe impl Sync for FileMapState {}

impl Default for FileMapState {
    fn default() -> Self {
        FileMapState {
            fd: -1,
            writable: false,
            base: std::ptr::null(),
            size: 0,
            copied: false,
        }
    }
}

impl Drop for FileMapState {
    fn drop(&mut self) {
        if !self.base.is_null() {
            if self.copied {
                // SAFETY: `read` allocated `base` with `copy_layout(size)`, and it is freed only
                // here. Every reference handed out borrows `self` (or holds an `Arc` to it), so
                // none outlive this call.
                unsafe { std::alloc::dealloc(self.base.cast_mut(), copy_layout(self.size)) };
            } else {
                // SAFETY: `base`/`size` describe the mapping created by a successful `mmap` in
                // `new`, which is unmapped only here; references are bounded as above.
                unsafe { libc::munmap(self.base as *mut u8 as *mut libc::c_void, self.size) };
            }
            self.base = std::ptr::null();
            self.size = 0;
        }
        if self.fd >= 0 {
            let _ = nix::unistd::close(self.fd);
            self.fd = -1;
        }
    }
}

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// Copies are aligned like a mapping, so a type that is aligned in a mapped file is aligned in a
/// copy of it.
const COPY_ALIGN: usize = 4096;

fn copy_layout(size: usize) -> std::alloc::Layout {
    std::alloc::Layout::from_size_align(size, COPY_ALIGN).expect("size checked by the constructor")
}

impl FileMapState {
    /// Memory map a region of the file object into current process.
    ///
    /// It takes ownership of the file object and will close it when the returned object is dropped.
    ///
    /// # Safety
    /// While any reference taken from the mapping is alive, nothing may write the mapped range of
    /// the file, in this process or another, except bytes that are only ever accessed through
    /// atomic operations. The file must not be truncated while it's mapped.
    pub unsafe fn new(
        file: File,
        offset: libc::off_t,
        size: usize,
        writable: bool,
    ) -> io::Result<Self> {
        if size == 0 || size > isize::MAX as usize {
            return Err(invalid_input("invalid mmap size"));
        }
        let prot = if writable {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        // SAFETY: a NULL hint lets the kernel choose the address; `file` is an open fd that
        // outlives the call, and `size` was checked to be non-zero. The result is checked for
        // `MAP_FAILED` below.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                prot,
                libc::MAP_NORESERVE | libc::MAP_SHARED,
                file.as_raw_fd(),
                offset,
            )
        } as *const u8;
        // `MAP_FAILED` is the documented failure value; the null check covers a libc that
        // returns NULL instead. Both leave `errno` set.
        if base as *mut core::ffi::c_void == libc::MAP_FAILED || base.is_null() {
            return Err(with_context(
                io::Error::last_os_error(),
                "failed to memory map file region into current process",
            ));
        }

        Ok(Self {
            fd: file.into_raw_fd(),
            writable,
            base,
            size,
            copied: false,
        })
    }

    /// Copy a region of the file into a page-aligned buffer, read-only.
    ///
    /// It takes ownership of the file object and will close it when the returned object is
    /// dropped. Unlike a mapping, later writes to the file are not seen, and the region must lie
    /// inside the file: a short file fails with `UnexpectedEof`.
    pub fn read(mut file: File, offset: u64, size: usize) -> io::Result<Self> {
        use std::io::{Read, Seek, SeekFrom};

        if size == 0 || size > isize::MAX as usize - COPY_ALIGN {
            return Err(invalid_input("invalid read size"));
        }
        file.seek(SeekFrom::Start(offset))?;
        let layout = copy_layout(size);
        // SAFETY: `size` is non-zero, so the layout is not zero-sized.
        let base = unsafe { std::alloc::alloc_zeroed(layout) };
        if base.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        // Owns `base` from here, so an error below frees it.
        let mut map = Self {
            fd: -1,
            writable: false,
            base,
            size,
            copied: true,
        };
        // SAFETY: `base` is a fresh, initialized (zeroed) allocation of `size` bytes that nothing
        // else references; the slice ends before `map` is returned.
        let buf = unsafe { std::slice::from_raw_parts_mut(base, size) };
        file.read_exact(buf)?;
        map.fd = file.into_raw_fd();
        Ok(map)
    }

    /// Bring a read-only region of the file into memory the way `source` says.
    ///
    /// # Safety
    /// For [`MetadataSource::Mmap`], the contract of [`FileMapState::new`]. A copy has none.
    pub unsafe fn load(
        source: MetadataSource,
        file: File,
        offset: u64,
        size: usize,
    ) -> io::Result<Self> {
        match source {
            MetadataSource::Mmap => {
                let offset = libc::off_t::try_from(offset)
                    .map_err(|_| invalid_input("invalid mmap offset"))?;
                // SAFETY: forwarded to the caller.
                unsafe { Self::new(file, offset, size, false) }
            }
            MetadataSource::Read => Self::read(file, offset, size),
        }
    }

    /// Get size of mapped region.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Cast a subregion of the mapped area to an object reference.
    pub fn get_ref<T: FromMapped>(&self, offset: usize) -> io::Result<&T> {
        let start = self.typed_range::<T>(offset, 1)?;
        // SAFETY: `typed_range` checked that the range lies inside the live mapping and is aligned
        // for `T`; `T: FromMapped` makes any bytes a valid `T`, and `new` requires them not to
        // change while borrowed. The reference borrows `self`, so the mapping outlives it.
        Ok(unsafe { &*start })
    }

    /// Cast a subregion of the mapped area to a mutable object reference.
    ///
    /// # Safety
    /// Nothing else, in this process or another, may access the borrowed range while borrowed.
    pub unsafe fn get_mut<T: FromMapped>(&mut self, offset: usize) -> io::Result<&mut T> {
        if !self.writable {
            return Err(invalid_input("mapping is read-only"));
        }
        let start = self.typed_range::<T>(offset, 1)?;
        // SAFETY: `typed_range` checked bounds and alignment and the mapping is writable; the
        // caller guarantees exclusive access to the range, and the reference borrows `self`
        // mutably.
        Ok(unsafe { &mut *start.cast_mut() })
    }

    /// Get an immutable slice of `T` at `offset` with `count` entries.
    pub fn get_slice<T: FromMapped>(&self, offset: usize, count: usize) -> io::Result<&[T]> {
        let start = self.typed_range::<T>(offset, count)?;
        // SAFETY: `typed_range` checked that `count` entries of `T` fit inside the live mapping (or
        // returned a dangling aligned pointer for an empty slice) and are aligned; validity follows
        // from `T: FromMapped` and the `new` contract as in `get_ref`.
        Ok(unsafe { std::slice::from_raw_parts(start, count) })
    }

    /// Get a mutable slice of `T` at `offset` with `count` entries.
    ///
    /// # Safety
    /// Nothing else, in this process or another, may access the borrowed range while borrowed.
    pub unsafe fn get_slice_mut<T: FromMapped>(
        &mut self,
        offset: usize,
        count: usize,
    ) -> io::Result<&mut [T]> {
        if !self.writable {
            return Err(invalid_input("mapping is read-only"));
        }
        let start = self.typed_range::<T>(offset, count)?;
        // SAFETY: bounds and alignment as in `get_slice`, the mapping is writable, and the caller
        // guarantees exclusive access to the range for the borrow of `self`.
        Ok(unsafe { std::slice::from_raw_parts_mut(start.cast_mut(), count) })
    }

    /// Validate `count` entries of `T` at `offset` and return an aligned start pointer.
    fn typed_range<T>(&self, offset: usize, count: usize) -> io::Result<*const T> {
        let size = count
            .checked_mul(size_of::<T>())
            .ok_or_else(|| invalid_input("mapped type size overflow"))?;
        if size == 0 {
            if offset > self.size {
                return Err(invalid_input("invalid range"));
            }
            return Ok(NonNull::<T>::dangling().as_ptr());
        }
        let start = self.validate_range(offset, size)?;
        if !start.cast::<T>().is_aligned() {
            return Err(invalid_input("unaligned mmap offset"));
        }
        Ok(start.cast())
    }

    /// Check whether the range [offset, offset + size) is valid and return the start address.
    pub fn validate_range(&self, offset: usize, size: usize) -> io::Result<*const u8> {
        if self.base.is_null()
            || offset
                .checked_add(size)
                .filter(|end| *end <= self.size)
                .is_none()
        {
            return Err(invalid_input("invalid range"));
        }
        Ok(self.base.wrapping_add(offset))
    }

    /// Add `offset` to the base pointer.
    ///
    /// # Safety
    /// The caller should ensure that `offset` is within range.
    pub unsafe fn offset(&self, offset: usize) -> *const u8 {
        self.base.wrapping_add(offset)
    }

    /// Sync mapped file data into disk.
    pub fn sync_data(&self) -> io::Result<()> {
        if self.fd < 0 {
            return Err(invalid_input("mapping has no file"));
        }
        // SAFETY: `fd` is the open descriptor owned by `self`; the temporary `File` is forgotten
        // instead of dropped, so it never closes the descriptor.
        let file = unsafe { File::from_raw_fd(self.fd) };
        let result = file.sync_data();
        std::mem::forget(file);
        result
    }
}

/// Duplicate a file object by `libc::dup()`.
pub fn clone_file(fd: RawFd) -> io::Result<File> {
    // SAFETY: `dup` has no memory-safety preconditions; on success it returns a fresh descriptor
    // that nothing else owns, so `File` may take ownership of it.
    unsafe {
        let fd = libc::dup(fd);
        if fd < 0 {
            return Err(with_context(
                io::Error::last_os_error(),
                "failed to dup bootstrap file fd",
            ));
        }
        Ok(File::from_raw_fd(fd))
    }
}

/// An immutable `[T]` view into a `FileMapState`, which stays mapped for as long as the view
/// exists.
pub struct MappedSlice<T> {
    ptr: *const T,
    len: usize,
    _map: Arc<FileMapState>,
}

impl<T: FromMapped> MappedSlice<T> {
    /// Create a view of `len` entries of `T` at `offset` in `map`.
    pub fn new(map: Arc<FileMapState>, offset: usize, len: usize) -> io::Result<Self> {
        let ptr = map.typed_range::<T>(offset, len)?;
        Ok(Self {
            ptr,
            len,
            _map: map,
        })
    }
}

impl<T> Clone for MappedSlice<T> {
    fn clone(&self) -> Self {
        Self {
            ptr: self.ptr,
            len: self.len,
            _map: self._map.clone(),
        }
    }
}

impl<T> Deref for MappedSlice<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        // SAFETY: `MappedSlice::new` checked range and alignment against the mapping, which `_map`
        // keeps alive for as long as this view, and `T: FromMapped` makes the bytes valid `T`s.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

// SAFETY: the view is a `&[T]` into a mapping kept alive by an `Arc`, so sending it is as sound as
// sending a `&[T]`, which requires `T: Sync`.
unsafe impl<T: Sync> Send for MappedSlice<T> {}
// SAFETY: sharing the view is as sound as sharing a `&[T]`, which requires `T: Sync`.
unsafe impl<T: Sync> Sync for MappedSlice<T> {}

/// A table of entries that is either built in memory or viewed in a mapped file.
#[derive(Clone)]
pub enum MappedOrOwned<T> {
    Owned(Vec<T>),
    Mapped(MappedSlice<T>),
}

impl<T: Clone> MappedOrOwned<T> {
    /// Get the entries as a vector, copying them out of the mapping first if needed.
    pub fn to_mut(&mut self) -> &mut Vec<T> {
        if let MappedOrOwned::Mapped(slice) = self {
            *self = MappedOrOwned::Owned(slice.to_vec());
        }
        match self {
            MappedOrOwned::Owned(v) => v,
            MappedOrOwned::Mapped(_) => unreachable!(),
        }
    }
}

impl<T> Default for MappedOrOwned<T> {
    fn default() -> Self {
        MappedOrOwned::Owned(Vec::new())
    }
}

impl<T> From<Vec<T>> for MappedOrOwned<T> {
    fn from(v: Vec<T>) -> Self {
        MappedOrOwned::Owned(v)
    }
}

impl<T> Deref for MappedOrOwned<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        match self {
            MappedOrOwned::Owned(v) => v,
            MappedOrOwned::Mapped(s) => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn mapped_slice_checks_range_and_alignment() {
        let temp = TempFile::new().unwrap();
        temp.as_file()
            .write_all(&[1u8, 0, 0, 0, 2, 0, 0, 0])
            .unwrap();
        let map = Arc::new(
            // SAFETY: the temp file is private to this test and is neither written nor truncated
            // while mapped.
            unsafe { FileMapState::new(temp.as_file().try_clone().unwrap(), 0, 8, false) }.unwrap(),
        );
        let view = MappedSlice::<u32>::new(map.clone(), 0, 2).unwrap();
        assert_eq!(u32::from_le(view[1]), 2);
        assert!(MappedSlice::<u32>::new(map.clone(), 1, 1).is_err());
        assert!(MappedSlice::<u32>::new(map.clone(), 4, 2).is_err());
        assert!(MappedSlice::<u32>::new(map.clone(), 0, usize::MAX).is_err());
        assert!(
            MappedSlice::<u32>::new(map.clone(), 8, 0)
                .unwrap()
                .is_empty()
        );
        assert!(MappedSlice::<u32>::new(map.clone(), 9, 0).is_err());
        drop(map);
        // The view keeps the mapping alive after the last other owner is gone.
        assert_eq!(u32::from_le(view[0]), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn mapped_or_owned_copies_before_mutation() {
        let temp = TempFile::new().unwrap();
        temp.as_file().write_all(&[7u8; 8]).unwrap();
        let map = Arc::new(
            // SAFETY: the temp file is private to this test and is neither written nor truncated
            // while mapped.
            unsafe { FileMapState::new(temp.as_file().try_clone().unwrap(), 0, 8, false) }.unwrap(),
        );
        let mut table = MappedOrOwned::Mapped(MappedSlice::<u8>::new(map, 0, 8).unwrap());
        table.to_mut().push(9);
        assert!(matches!(table, MappedOrOwned::Owned(_)));
        assert_eq!(&table[..], &[7, 7, 7, 7, 7, 7, 7, 7, 9]);
        assert_eq!(std::fs::read(temp.as_path()).unwrap(), vec![7u8; 8]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn create_file_map_object() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/bootstrap/rafs-v5.boot");
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .unwrap();
        // SAFETY: the fixture bootstrap is read-only test data that nothing writes while it is
        // mapped.
        let map = unsafe { FileMapState::new(file, 0, 4096, false) }.unwrap();

        let magic = map.get_ref::<u32>(0).unwrap();
        assert_eq!(u32::from_le(*magic), 0x52414653);

        map.get_ref::<u32>(4096).unwrap_err();
        let _ = map.get_ref::<u32>(4092).unwrap();
        let _ = map.get_ref::<u32>(0).unwrap();
        map.validate_range(4096, 1).unwrap_err();
        let _ = map.validate_range(4095, 1).unwrap();
        let _ = map.validate_range(0, 1).unwrap();
        drop(map);
    }

    fn file_with(bytes: &[u8]) -> File {
        let temp = tempfile::tempfile().unwrap();
        (&temp).write_all(bytes).unwrap();
        temp
    }

    /// A copy hands out the same bytes as a mapping of the same region, page-aligned.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn copy_matches_mapping() {
        let bytes: Vec<u8> = (0..3 * 4096u32).map(|i| (i * 7) as u8).collect();
        // SAFETY: the temporary file is not written while mapped.
        let mapped = unsafe { FileMapState::new(file_with(&bytes), 0, 8192, false) }.unwrap();
        let copied = FileMapState::read(file_with(&bytes), 0, 8192).unwrap();
        assert_eq!(
            mapped.get_slice::<u8>(0, 8192).unwrap(),
            copied.get_slice::<u8>(0, 8192).unwrap()
        );
        assert!((copied.get_slice::<u8>(0, 1).unwrap().as_ptr() as usize).is_multiple_of(4096));
    }

    #[test]
    fn copy_reads_the_region_and_checks_ranges() {
        let bytes: Vec<u8> = (0..64u8).collect();
        let copied = FileMapState::read(file_with(&bytes), 8, 32).unwrap();
        assert_eq!(copied.size(), 32);
        assert_eq!(copied.get_slice::<u8>(0, 32).unwrap(), &bytes[8..40]);
        assert_eq!(
            *copied.get_ref::<u64>(8).unwrap(),
            u64::from_ne_bytes(bytes[16..24].try_into().unwrap())
        );
        assert!(copied.get_ref::<u64>(4).is_err(), "unaligned");
        assert!(copied.get_slice::<u8>(1, 32).is_err(), "past the end");
        let slice = MappedSlice::<u32>::new(Arc::new(copied), 4, 7).unwrap();
        assert_eq!(slice.len(), 7);
    }

    #[test]
    fn copy_rejects_a_short_file_and_an_empty_region() {
        let err = FileMapState::read(file_with(&[0; 16]), 8, 16)
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(FileMapState::read(file_with(&[0; 16]), 0, 0).is_err());
    }

    #[test]
    fn copy_is_read_only() {
        let mut copied = FileMapState::read(file_with(&[0; 64]), 0, 64).unwrap();
        // SAFETY: nothing else accesses the copy; the call must fail before handing out a reference.
        assert!(unsafe { copied.get_mut::<u64>(0) }.is_err());
    }

    #[test]
    fn create_default_file_map_object() {
        let map = FileMapState::default();
        drop(map);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn test_file_map_error() {
        let temp = TempFile::new().unwrap();
        temp.as_file().set_len(4096).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        // SAFETY: the temp file is private to this test; the mapping attempt fails before any
        // access.
        assert!(unsafe { FileMapState::new(file, 0, 4096, true) }.is_err());

        let temp = TempFile::new().unwrap();
        temp.as_file().set_len(4096).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        // SAFETY: the temp file is private to this test and is neither written nor truncated while
        // mapped.
        let mut map = unsafe { FileMapState::new(file, 0, 4096, false) }.unwrap();
        assert!(map.get_slice::<u64>(0, usize::MAX).is_err());
        assert!(map.get_slice::<u64>(usize::MAX, 1).is_err());
        assert!(map.get_slice::<u64>(4096, 4096).is_err());
        assert!(map.get_slice::<u64>(0, 128).is_ok());
        assert!(map.get_slice::<u64>(0, 0).is_ok());

        // SAFETY: the mapping is read-only, so every call returns an error before creating a
        // reference.
        assert!(unsafe { map.get_slice_mut::<u64>(0, usize::MAX) }.is_err());
        // SAFETY: the mapping is read-only, so every call returns an error before creating a
        // reference.
        assert!(unsafe { map.get_slice_mut::<u64>(usize::MAX, 1) }.is_err());
        // SAFETY: the mapping is read-only, so every call returns an error before creating a
        // reference.
        assert!(unsafe { map.get_slice_mut::<u64>(4096, 4096) }.is_err());
        // Read-only mapping: mutable access is refused even for an in-range request.
        // SAFETY: the mapping is read-only, so every call returns an error before creating a
        // reference.
        assert!(unsafe { map.get_slice_mut::<u64>(0, 128) }.is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn typed_mapping_checks_alignment_permissions_and_empty_state() {
        let temp = TempFile::new().unwrap();
        temp.as_file().set_len(4096).unwrap();
        let mut map =
            // SAFETY: the temp file is private to this test and is only written through this
            // mapping.
            unsafe { FileMapState::new(temp.as_file().try_clone().unwrap(), 0, 4096, true) }
                .unwrap();
        // SAFETY: the test holds the only handle that accesses the mapping, so the mutable
        // reference is exclusive and is dropped before the shared read.
        unsafe {
            assert!(map.get_ref::<u32>(1).is_err());
            assert!(map.get_mut::<u32>(1).is_err());
            assert!(map.get_slice::<u32>(1, 1).is_err());
            assert!(map.get_slice_mut::<u32>(1, 1).is_err());
            assert!(map.get_ref::<u64>(4092).is_err());
            *map.get_mut::<u32>(4).unwrap() = 42;
            assert_eq!(*map.get_ref::<u32>(4).unwrap(), 42);
        }
        map.sync_data().unwrap();
        drop(map);
        let mut map =
            // SAFETY: the temp file is private to this test and is neither written nor truncated
            // while mapped.
            unsafe { FileMapState::new(temp.as_file().try_clone().unwrap(), 0, 4096, false) }
                .unwrap();
        // SAFETY: the mapping is read-only, so the mutable accessors fail before creating
        // references.
        unsafe {
            assert_eq!(*map.get_ref::<u32>(4).unwrap(), 42);
            assert!(map.get_mut::<u32>(4).is_err());
            assert!(map.get_slice_mut::<u8>(0, 1).is_err());
        }
        let mut empty = FileMapState::default();
        // SAFETY: the empty map has no memory, so only zero-sized requests succeed and none
        // dereferences memory.
        unsafe {
            assert!(empty.get_ref::<[u8; 0]>(0).is_ok());
            assert!(empty.get_slice::<u8>(0, 0).is_ok());
            assert!(empty.get_slice::<u8>(1, 0).is_err());
            assert!(empty.get_ref::<u8>(0).is_err());
            assert!(empty.get_mut::<[u8; 0]>(0).is_err());
        }
        assert!(empty.sync_data().is_err());
        assert!(empty.validate_range(0, 0).is_err());
        assert!(
            // SAFETY: the size check rejects 0 before any mapping is created.
            unsafe { FileMapState::new(temp.as_file().try_clone().unwrap(), 0, 0, false) }.is_err()
        );
    }
}
