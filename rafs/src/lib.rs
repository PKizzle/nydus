// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! RAFS: a chunk dedup, on-demand loading, readonly fuse filesystem.
//!
//! The Rafs filesystem is blob based readonly filesystem with chunk deduplication. A Rafs
//! filesystem is composed up of a metadata blob and zero or more data blobs. A blob is just a
//! plain object containing data chunks. Data chunks may be compressed, encrypted and deduplicated
//! by chunk content digest value. When Rafs file is used for container images, Rafs metadata blob
//! contains all filesystem metadatas, such as directory, file name, permission etc. Actually file
//! contents are divided into chunks and stored into data blobs. Rafs may built one data blob for
//! each container image layer or build a single data blob for the whole image, according to
//! building options.
//!
//! There are several versions of Rafs filesystem defined:
//! - V4: the original Rafs filesystem format
//! - V5: an optimized version based on V4 with metadata direct mapping, data prefetching etc.
//! - V6: a redesigned version to reduce metadata blob size and inter-operable with in kernel erofs,
//!   better support of virtio-fs.
//!
//! The nydus-rafs crate depends on the nydus-storage crate to access metadata and data blobs and
//! improve performance by caching data on local storage. The nydus-rafs itself includes two main
//! sub modules:
//! - [fs](fs/index.html): the Rafs core to glue fuse, storage backend and filesystem metadata.
//! - [metadata](metadata/index.html): defines and accesses Rafs filesystem metadata.
//!
//! For more information, please refer to
//! [Dragonfly Image Service](https://github.com/dragonflyoss/nydus)

#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate nydus_storage as storage;

use std::any::Any;
use std::borrow::Cow;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufWriter, Error, Read, Result, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nydus_storage::StorageError;

use crate::metadata::{RafsInodeExt, RafsSuper};

#[cfg(feature = "virtio-fs")]
pub mod blobfs;
pub mod fs;
pub mod metadata;
#[cfg(test)]
pub mod mock;
pub mod prefetch;

/// Error codes for rafs related operations.
#[derive(thiserror::Error, Debug)]
pub enum RafsError {
    #[error("Operation is not supported.")]
    Unsupported,
    #[error("Rafs is not initialized.")]
    Uninitialized,
    #[error("Rafs is already mounted.")]
    AlreadyMounted,
    #[error("Failed to read metadata: {0}`")]
    ReadMetadata(#[source] Error, String),
    #[error("Failed to load config: {0}`")]
    LoadConfig(#[source] Error),
    #[error("Failed to parse config: {0}`")]
    ParseConfig(#[source] serde_json::Error),
    #[error("Failed to create swap backend: {0}`")]
    SwapBackend(#[source] Error),
    #[error("Failed to fill superBlock: {0}`")]
    FillSuperBlock(#[source] Error),
    #[error("Failed to create device: {0}`")]
    CreateDevice(#[source] Error),
    #[error("Failed to prefetch data: {0}`")]
    Prefetch(String),
    #[error("Failed to configure device: {0}`")]
    Configure(String),
    #[error("Incompatible RAFS version: `{0}`")]
    Incompatible(u16),
    #[error("Illegal meta struct, type is `{0:?}` and content is `{1}`")]
    IllegalMetaStruct(MetaType, String),
    #[error("Invalid image data")]
    InvalidImageData,
    /// The on-disk metadata is malformed, inconsistent or fails validation.
    ///
    /// Every one of these used to be an EINVAL error macro, whose message was dropped before it could be
    /// logged; the string is the description the code already wrote.
    #[error("{0}")]
    InvalidMetadata(String),
    /// A name, inode number or index does not exist in the filesystem.
    ///
    /// Maps to `ENOENT`, which is a protocol answer rather than a failure: the kernel caches
    /// negative lookups on it.
    #[error("{0}")]
    NotFound(String),
    /// The operation requires a directory and the inode is not one.
    #[error("{0}")]
    NotDirectory(String),
    /// A table, index or handle referenced by the metadata is unusable.
    #[error("{0}")]
    BadDescriptor(String),
    /// Access to the object is not permitted.
    #[error("{0}")]
    PermissionDenied(String),
    /// The storage layer failed to serve blob data or metadata.
    ///
    /// Boxed to keep `RafsError` small: it is the error half of nearly every signature in this
    /// crate, and `StorageError` is several words wide.
    #[error("{0}")]
    Storage(#[source] Box<StorageError>),
    /// An I/O operation against the bootstrap or a blob failed.
    ///
    /// Kept raw (never re-wrapped) so `source_errno` can recover its errno at the FUSE
    /// boundary. Context comes from the caller: the outer variants above (`FillSuperBlock`,
    /// `ReadMetadata`, ...) name which stage of the load or store this happened in.
    #[error("{0}")]
    Io(#[from] Error),
}

impl RafsError {
    /// The errno to answer the kernel with for this error.
    ///
    /// RAFS sits under FUSE, where the only thing the other side understands is an errno, and
    /// several of them are protocol rather than failure -- `ENOENT` from a lookup is how a
    /// negative dentry is cached, `ENOTDIR` is how `readdir` on a file is refused. Those have
    /// dedicated variants above so this table can reproduce them exactly; anything else defers
    /// to an errno recovered from the chain (a cache write that hit `ENOSPC`, say) and falls
    /// back to `EIO`.
    /// The `ErrorKind` of the first `io::Error` on the chain, if any.
    ///
    /// `RafsError` wraps rather than flattens its I/O failures, so callers that used to match
    /// on `e.kind()` -- the inode-table loader ends its loop on `UnexpectedEof` -- have to ask
    /// the chain instead of the outer type.
    pub fn io_error_kind(&self) -> Option<std::io::ErrorKind> {
        let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(self);
        while let Some(e) = cur {
            if let Some(ioe) = e.downcast_ref::<Error>() {
                return Some(ioe.kind());
            }
            cur = e.source();
        }
        None
    }

    pub fn errno(&self) -> i32 {
        match self {
            RafsError::NotFound(_) => libc::ENOENT,
            RafsError::NotDirectory(_) => libc::ENOTDIR,
            RafsError::BadDescriptor(_) => libc::EBADF,
            RafsError::PermissionDenied(_) => libc::EACCES,
            RafsError::Unsupported => libc::EOPNOTSUPP,
            RafsError::InvalidMetadata(_)
            | RafsError::Uninitialized
            | RafsError::AlreadyMounted
            | RafsError::Incompatible(_)
            | RafsError::IllegalMetaStruct(..)
            | RafsError::InvalidImageData
            | RafsError::ParseConfig(_)
            | RafsError::Configure(_) => libc::EINVAL,
            _ => nydus_utils::source_errno(self).unwrap_or(libc::EIO),
        }
    }
}

impl From<StorageError> for RafsError {
    fn from(e: StorageError) -> Self {
        RafsError::Storage(Box::new(e))
    }
}

/// Boundary conversion for the places pinned to `std::io::Error` by an external trait.
///
/// Permanent, not a migration shim: `impl FileSystem for Rafs`, blobfs' `sync_io` and the C API
/// are all pinned, and the kernel behind them reads `raw_os_error()` and nothing else. A
/// `Custom` error would report `None` there and be answered as `EIO`, so this deliberately
/// produces a raw `Os` error and drops the message -- callers that want the message must log it
/// before converting, which is what `fuse_err` in `fs.rs` does.
impl From<RafsError> for Error {
    fn from(e: RafsError) -> Self {
        Error::from_raw_os_error(e.errno())
    }
}

#[derive(Debug)]
pub enum MetaType {
    Regular,
    Dir,
    Symlink,
}

/// Specialized version of std::result::Result<> for Rafs.
pub type RafsResult<T> = std::result::Result<T, RafsError>;

/// Handler to read file system bootstrap.
pub type RafsIoReader = Box<dyn RafsIoRead>;

/// A helper trait for RafsIoReader.
pub trait RafsIoRead: Read + AsRawFd + Seek + Send {}

impl RafsIoRead for File {}

/// Handler to write file system bootstrap.
pub type RafsIoWriter = Box<dyn RafsIoWrite>;

/// A helper trait for RafsIoWriter.
pub trait RafsIoWrite: Write + Seek + 'static {
    fn as_any(&self) -> &dyn Any;

    fn validate_alignment(&mut self, size: usize, alignment: usize) -> Result<usize> {
        if alignment != 0 {
            let cur = self.stream_position()?;

            if (size & (alignment - 1) != 0) || (cur & (alignment as u64 - 1) != 0) {
                return Err(Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unaligned data",
                ));
            }
        }

        Ok(size)
    }

    /// write padding to align to RAFS_ALIGNMENT.
    fn write_padding(&mut self, size: usize) -> Result<()> {
        if size > WRITE_PADDING_DATA.len() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid padding size",
            ));
        }
        self.write_all(&WRITE_PADDING_DATA[0..size])
    }

    /// Seek the writer to the end.
    fn seek_to_end(&mut self) -> Result<u64> {
        self.seek(SeekFrom::End(0)).map_err(|e| {
            error!("Seeking to end fails, {}", e);
            e
        })
    }

    /// Seek the writer to the `offset`.
    fn seek_offset(&mut self, offset: u64) -> Result<u64> {
        self.seek(SeekFrom::Start(offset)).map_err(|e| {
            error!("Seeking to offset {} from start fails, {}", offset, e);
            e
        })
    }

    /// Seek the writer to current position plus the specified offset.
    fn seek_current(&mut self, offset: i64) -> Result<u64> {
        self.seek(SeekFrom::Current(offset))
    }

    /// Do some finalization works.
    fn finalize(&mut self, _name: Option<String>) -> anyhow::Result<()> {
        Ok(())
    }

    /// Return a slice to get all data written.
    ///
    /// No more data should be written after calling as_bytes().
    fn as_bytes(&mut self) -> std::io::Result<Cow<'_, [u8]>> {
        unimplemented!()
    }
}

impl RafsIoWrite for File {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Rust file I/O is un-buffered by default. If we have many small write calls
// to a file, should use BufWriter. BufWriter maintains an in-memory buffer
// for writing, minimizing the number of system calls required.
impl RafsIoWrite for BufWriter<File> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

const WRITE_PADDING_DATA: [u8; 64] = [0u8; 64];

impl dyn RafsIoRead {
    /// Seek the reader to next aligned position.
    pub fn seek_to_next_aligned(&mut self, last_read_len: usize, alignment: usize) -> Result<u64> {
        let suffix = last_read_len & (alignment - 1);
        let offset = if suffix == 0 { 0 } else { alignment - suffix };

        self.seek(SeekFrom::Current(offset as i64)).map_err(|e| {
            error!("Seeking to offset {} from current fails, {}", offset, e);
            e
        })
    }

    /// Move the reader current position forward with `plus_offset` bytes.
    pub fn seek_plus_offset(&mut self, plus_offset: i64) -> Result<u64> {
        // Seek should not fail otherwise rafs goes insane.
        self.seek(SeekFrom::Current(plus_offset)).map_err(|e| {
            error!(
                "Seeking to offset {} from current fails, {}",
                plus_offset, e
            );
            e
        })
    }

    /// Seek the reader to the `offset`.
    pub fn seek_to_offset(&mut self, offset: u64) -> Result<u64> {
        self.seek(SeekFrom::Start(offset)).map_err(|e| {
            error!("Seeking to offset {} from start fails, {}", offset, e);
            e
        })
    }

    /// Seek the reader to the end.
    pub fn seek_to_end(&mut self, offset: i64) -> Result<u64> {
        self.seek(SeekFrom::End(offset)).map_err(|e| {
            error!("Seeking to end fails, {}", e);
            e
        })
    }

    /// Create a reader from a file path.
    pub fn from_file(path: impl AsRef<Path>) -> RafsResult<RafsIoReader> {
        let f = File::open(&path).map_err(|e| {
            RafsError::ReadMetadata(e, path.as_ref().to_string_lossy().into_owned())
        })?;

        Ok(Box::new(f))
    }
}

///  Iterator to walk all inodes of a Rafs filesystem.
pub struct RafsIterator<'a> {
    _rs: &'a RafsSuper,
    cursor_stack: Vec<(Arc<dyn RafsInodeExt>, PathBuf)>,
}

impl<'a> RafsIterator<'a> {
    /// Create a new iterator to visit a Rafs filesystem.
    pub fn new(rs: &'a RafsSuper) -> Self {
        let cursor_stack = match rs.get_extended_inode(rs.superblock.root_ino(), false) {
            Ok(node) => {
                let path = PathBuf::from("/");
                vec![(node, path)]
            }
            Err(e) => {
                error!(
                    "failed to get root inode from the bootstrap {}, damaged or malicious file?",
                    e
                );
                vec![]
            }
        };

        RafsIterator {
            _rs: rs,
            cursor_stack,
        }
    }
}

impl Iterator for RafsIterator<'_> {
    type Item = (Arc<dyn RafsInodeExt>, PathBuf);

    fn next(&mut self) -> Option<Self::Item> {
        let (node, path) = self.cursor_stack.pop()?;
        if node.is_dir() {
            let children = 0..node.get_child_count();
            for idx in children.rev() {
                if let Ok(child) = node.get_child_by_index(idx) {
                    let child_path = path.join(child.name());
                    self.cursor_stack.push((child, child_path));
                } else {
                    error!(
                        "failed to get child inode from the bootstrap, damaged or malicious file?"
                    );
                }
            }
        }
        Some((node, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::RafsMode;
    use std::fs::OpenOptions;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_rafs_io_writer() {
        let mut file = TempFile::new().unwrap().into_file();

        assert!(file.validate_alignment(2, 8).is_err());
        assert!(file.validate_alignment(7, 8).is_err());
        assert!(file.validate_alignment(9, 8).is_err());
        assert!(file.validate_alignment(8, 8).is_ok());

        file.write_all(&[0x0u8; 7]).unwrap();
        assert!(file.validate_alignment(8, 8).is_err());
        {
            let obj: &mut dyn RafsIoWrite = &mut file;
            obj.write_padding(1).unwrap();
        }
        assert!(file.validate_alignment(8, 8).is_ok());
        file.write_all(&[0x0u8; 1]).unwrap();
        assert!(file.validate_alignment(8, 8).is_err());

        let obj: &mut dyn RafsIoRead = &mut file;
        assert_eq!(obj.seek_to_offset(0).unwrap(), 0);
        assert_eq!(obj.seek_plus_offset(7).unwrap(), 7);
        assert_eq!(obj.seek_to_next_aligned(7, 8).unwrap(), 8);
        assert_eq!(obj.seek_plus_offset(7).unwrap(), 15);
    }

    #[test]
    fn test_rafs_iterator() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/bootstrap/rafs-v5.boot");
        let bootstrap = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .unwrap();
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: false,
            ..Default::default()
        };
        rs.load(&mut (Box::new(bootstrap) as RafsIoReader)).unwrap();
        let iter = RafsIterator::new(&rs);

        let mut last = false;
        for (idx, (_node, path)) in iter.enumerate() {
            assert!(!last);
            if idx == 1 {
                assert_eq!(path, PathBuf::from("/bin"));
            } else if idx == 2 {
                assert_eq!(path, PathBuf::from("/boot"));
            } else if idx == 3 {
                assert_eq!(path, PathBuf::from("/dev"));
            } else if idx == 10 {
                assert_eq!(path, PathBuf::from("/etc/DIR_COLORS.256color"));
            } else if idx == 11 {
                assert_eq!(path, PathBuf::from("/etc/DIR_COLORS.lightbgcolor"));
            } else if path == Path::new("/var/yp") {
                last = true;
            }
        }
        assert!(last);
    }

    /// Every variant the FUSE boundary can be handed must map to the errno the kernel expects.
    ///
    /// Before the migration these were raw `Os` errors built by the error macros, so the
    /// errno came for free (and the message did not). Now the errno comes from this table, and
    /// a variant added without a row would silently start answering `EIO`.
    #[test]
    fn rafs_error_errno_table() {
        let cases: Vec<(RafsError, i32)> = vec![
            (RafsError::NotFound("x".into()), libc::ENOENT),
            (RafsError::NotDirectory("x".into()), libc::ENOTDIR),
            (RafsError::BadDescriptor("x".into()), libc::EBADF),
            (RafsError::PermissionDenied("x".into()), libc::EACCES),
            (RafsError::Unsupported, libc::EOPNOTSUPP),
            (RafsError::InvalidMetadata("x".into()), libc::EINVAL),
            (RafsError::Uninitialized, libc::EINVAL),
            (RafsError::AlreadyMounted, libc::EINVAL),
            (RafsError::Incompatible(7), libc::EINVAL),
            (RafsError::InvalidImageData, libc::EINVAL),
            (RafsError::Configure("x".into()), libc::EINVAL),
            (RafsError::Prefetch("x".into()), libc::EIO),
        ];
        for (err, want) in cases {
            assert_eq!(err.errno(), want, "wrong errno for {:?}", err);
            assert_eq!(
                Error::from(err).raw_os_error(),
                Some(want),
                "the io::Error conversion must keep the errno recoverable"
            );
        }
    }

    /// The disk-full path, end to end through rafs.
    ///
    /// A cache `pwrite` that fails with `ENOSPC` becomes `StorageError::CacheIo`, travels up as
    /// `RafsError::Storage`, and must still be `ENOSPC` when it reaches the kernel -- answering
    /// `EIO` there would tell a reader "I/O error" for a full disk, and answering `FAN_ALLOW`
    /// would hand it zeros. Nothing in the chain may re-wrap the raw `Os` error.
    #[test]
    fn enospc_survives_the_trip_through_rafs() {
        let cache_err = StorageError::cache_io("pwrite", Error::from_raw_os_error(libc::ENOSPC));
        let err = RafsError::from(cache_err);

        assert_eq!(nydus_utils::source_errno(&err), Some(libc::ENOSPC));
        assert_eq!(err.errno(), libc::ENOSPC);
        assert_eq!(Error::from(err).raw_os_error(), Some(libc::ENOSPC));
    }

    /// A storage failure with no errno behind it falls back to `EIO`, not to a guess.
    #[test]
    fn storage_error_without_an_errno_is_eio() {
        let err = RafsError::from(StorageError::ShortWrite {
            expected: 4096,
            written: 17,
        });
        assert_eq!(nydus_utils::source_errno(&err), None);
        assert_eq!(err.errno(), libc::EIO);
    }

    /// `io_error_kind` has to see through the wrapper, because the v5 inode-table loader ends
    /// its loop on `UnexpectedEof` and would otherwise read past the table.
    #[test]
    fn io_error_kind_sees_through_the_wrapper() {
        let err = RafsError::Io(Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        assert_eq!(err.io_error_kind(), Some(std::io::ErrorKind::UnexpectedEof));
        assert_eq!(RafsError::Unsupported.io_error_kind(), None);
    }
}
