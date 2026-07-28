// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Chunked blob storage service to support Rafs filesystem.
//!
//! The Rafs filesystem is blob based filesystem with chunk deduplication. A Rafs filesystem is
//! composed up of a metadata blob and zero or more data blobs. A blob is just a plain object
//! storage containing data chunks. Data chunks may be compressed, encrypted and deduplicated by
//! content digest value. When Rafs file is used for container images, Rafs metadata blob contains
//! all filesystem metadatas, such as directory, file name, permission etc. Actually file contents
//! are split into chunks and stored into data blobs. Rafs may build one data blob for each
//! container image layer or build a  single data blob for the whole image, according to building
//! options.
//!
//! The nydus-storage crate is used to manage and access chunked blobs for Rafs filesystem, which
//! contains three layers:
//! - [Backend](backend/index.html): access raw blob objects on remote storage backends.
//! - [Cache](cache/index.html): cache remote blob contents onto local storage in forms
//!   optimized for performance.
//! - [Device](device/index.html): public APIs for chunked blobs
//!
//! There are several core abstractions provided by the public APIs:
//! - [BlobInfo](device/struct.BlobInfo.html): provides information about blobs, which is typically
//!   constructed from the `blob array` in Rafs filesystem metadata.
//! - [BlobDevice](device/struct.BlobDevice.html): provides access to all blobs of a Rafs filesystem,
//!   which is constructed from an array of [BlobInfo](device/struct.BlobInfo.html) objects.
//! - [BlobChunkInfo](device/trait.BlobChunkInfo.html): provides information about a data chunk, which
//!   is loaded from Rafs metadata.
//! - [BlobIoDesc](device/struct.BlobIoDesc.html): a blob IO descriptor, containing information for a
//!   continuous IO range within a chunk.
//! - [BlobIoVec](device/struct.BlobIoVec.html): a scatter/gather list for blob IO operation, containing
//!   one or more blob IO descriptors
//!
//! To read data from the Rafs filesystem, the Rafs filesystem driver will prepare a
//! [BlobIoVec](device/struct.BlobIoVec.html)
//! object and submit it to the corresponding [BlobDevice](device/struct.BlobDevice.html)
//!  object to actually execute the IO
//! operations.
#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;

pub mod backend;
pub mod cache;
pub mod device;
pub mod factory;
pub mod meta;
//pub mod remote;
#[cfg(test)]
pub(crate) mod test;
pub mod utils;

// A helper to impl RafsChunkInfo for upper layers like Rafs different metadata mode.
#[doc(hidden)]
#[macro_export]
macro_rules! impl_getter {
    ($G: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            self.$F
        }
    };
}

/// Default blob chunk size.
pub const RAFS_DEFAULT_CHUNK_SIZE: u64 = 1024 * 1024;
/// Maximum blob chunk size, 16MB.
pub const RAFS_MAX_CHUNK_SIZE: u64 = 1024 * 1024 * 16;
/// Maximum numbers of chunk per data blob
pub const RAFS_MAX_CHUNKS_PER_BLOB: u32 = 1u32 << 24;
/// Generate maximum gap between chunks from merging size.
pub const RAFS_BATCH_SIZE_TO_GAP_SHIFT: u64 = 7;

/// Error codes related to storage subsystem.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The operation is not supported by this storage configuration.
    #[error("unsupported storage operation")]
    Unsupported,
    /// A backend read did not complete in time.
    #[error("timeout when reading data from storage backend")]
    Timeout,
    /// A guest-memory slice could not be addressed.
    #[error("{0}")]
    VolatileSlice(#[source] vm_memory::VolatileMemoryError),
    /// An offset or length calculation overflowed.
    #[error("memory overflow when doing storage backend IO")]
    MemOverflow,
    /// The supplied address ranges are not contiguous.
    #[error("address ranges are not continuous")]
    NotContinuous,
    /// The chunk index is out of range for the blob.
    #[error("Wrong cache index {0}")]
    CacheIndex(#[source] std::io::Error),
    /// The proxy refused the request.
    #[error("proxy forbidden: {0}")]
    ProxyForbidden(String),
    /// The proxy rate-limited the request.
    #[error("proxy rate limited: {0}")]
    ProxyLimited(String),
    /// A blob's compression context table could not be read or trusted.
    #[error("{0}")]
    Meta(#[from] crate::meta::MetaError),
    /// A storage backend refused, or failed to serve, a request.
    ///
    /// Boxed because [`crate::backend::BackendError::CopyData`] carries a `StorageError` back
    /// the other way; storing either inline would make both enums infinitely sized.
    #[error("{0}")]
    Backend(#[source] Box<crate::backend::BackendError>),
    /// The configuration the storage layer was handed does not describe a usable blob.
    #[error("{0}")]
    Config(#[from] nydus_api::ConfigError),
    /// A caller passed an argument the storage layer cannot act on.
    #[error("{0}")]
    InvalidArgument(String),
    /// The storage object is not in a state where the operation makes sense.
    #[error("{0}")]
    InvalidState(String),
    /// Data read back from the cache or a blob is not what it claimed to be.
    #[error("{0}")]
    InvalidData(String),
    /// A cache write completed with fewer bytes than asked for.
    ///
    /// Carries no errno, so the fanotify deny path falls back to `EIO` -- which is what the
    /// old `eio!("failed to write data to file cache")` produced.
    #[error("short write to the blob cache: wrote {written} of {expected} bytes")]
    ShortWrite {
        /// Bytes the caller asked to write.
        expected: usize,
        /// Bytes actually written.
        written: usize,
    },
    /// An I/O operation against the blob device failed.
    ///
    /// The blob device sits under `FileReadWriteVolatile` and the FUSE `ZeroCopyWriter`, both of
    /// which are pinned to `io::Error` by external traits. `source` is whatever came back across
    /// that pin -- either a raw `Os` error or a `Custom` one still carrying a `StorageError`
    /// payload -- and `source_errno` sees through both, so an errno raised deeper down (a cache
    /// `pwrite` hitting `ENOSPC`, say) survives the round trip.
    #[error("failed to {op} the blob device: {source}")]
    DeviceIo {
        /// The operation attempted, e.g. `read`.
        op: &'static str,
        /// The error as it came back across the `io::Error` pin.
        #[source]
        source: std::io::Error,
    },
    /// A read or write against the local cache failed.
    ///
    /// This is the errno carrier the on-demand path depends on. A `pwrite` into a blob's cache
    /// file can fail with `ENOSPC` or `EDQUOT`, and the fanotify handler has to answer the
    /// kernel's permission event with that exact errno -- so `source` holds the raw `Os` error
    /// and is never re-wrapped into a `Custom` one.
    #[error("failed to {op} the blob cache: {source}")]
    CacheIo {
        /// The operation attempted, e.g. `pwrite` or `mmap`.
        op: &'static str,
        /// The OS error, kept raw so its errno stays recoverable.
        #[source]
        source: std::io::Error,
    },
}

impl StorageError {
    /// Build a [`StorageError::CacheIo`] for `op`.
    pub fn cache_io(op: &'static str, source: std::io::Error) -> Self {
        StorageError::CacheIo { op, source }
    }

    /// Build a [`StorageError::Backend`], boxing the backend error.
    pub fn backend(source: crate::backend::BackendError) -> Self {
        StorageError::Backend(Box::new(source))
    }
}

impl From<crate::backend::BackendError> for StorageError {
    fn from(e: crate::backend::BackendError) -> Self {
        StorageError::backend(e)
    }
}

/// Boundary conversion for the places pinned to `std::io::Error` by an external trait.
///
/// This one is permanent, not a migration shim: `FileReadWriteVolatile`, the FUSE server and
/// the C API all require an `io::Error`, and the kernel on the other side of them understands
/// an errno and nothing else.
///
/// An errno recovered from anywhere on the chain wins, so a failure that started as a real
/// syscall failure (`ENOSPC` from a cache write, say) arrives at the fanotify or FUSE boundary
/// as that errno rather than as a generic one. Only when there is no errno to recover does the
/// variant decide the kind.
impl From<StorageError> for std::io::Error {
    fn from(e: StorageError) -> Self {
        if let Some(errno) = nydus_utils::source_errno(&e) {
            return std::io::Error::from_raw_os_error(errno);
        }
        let kind = match &e {
            StorageError::Unsupported => std::io::ErrorKind::Unsupported,
            StorageError::Timeout => std::io::ErrorKind::TimedOut,
            StorageError::InvalidArgument(_) | StorageError::InvalidState(_) => {
                std::io::ErrorKind::InvalidInput
            }
            StorageError::InvalidData(_) => std::io::ErrorKind::InvalidData,
            _ => std::io::ErrorKind::Other,
        };
        std::io::Error::new(kind, e)
    }
}

/// Specialized std::result::Result for storage subsystem.
pub type StorageResult<T> = std::result::Result<T, StorageError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_error_proxy_forbidden_display() {
        let err = StorageError::ProxyForbidden("access denied".to_string());
        assert!(format!("{}", err).contains("proxy forbidden"));
    }

    #[test]
    fn test_storage_error_proxy_limited_display() {
        let err = StorageError::ProxyLimited("rate limited".to_string());
        assert!(format!("{}", err).contains("proxy rate limited"));
    }
}
