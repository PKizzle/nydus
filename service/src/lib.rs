// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Nydus Image Service Management Framework
//!
//! The `nydus-service` crate provides facilities to manage Nydus services, such as:
//! - `blobfs`: share processed RAFS metadata/data blobs to guest by virtio-fs, so the RAFS
//!   filesystem can be mounted by EROFS inside guest.
//! - `blockdev`: compose processed RAFS metadata/data as a block device, so it can be used as
//!   backend for virtio-blk.
//! - `fanotify`: mount RAFS filesystems using EROFS + fanotify pre-content hooks (Linux ≥ 6.14).
//! - `fuse`: mount RAFS filesystems as FUSE filesystems.

#[macro_use]
extern crate log;
#[macro_use]
extern crate nydus_api;

use std::fmt::{self, Display};
use std::io;
use std::str::FromStr;
use std::sync::mpsc::{RecvError, SendError};

use fuse_backend_rs::Error as FuseError;
use fuse_backend_rs::api::vfs::VfsError;
use fuse_backend_rs::transport::Error as FuseTransportError;
use nydus_api::{ConfigV2, DaemonErrorKind};
use nydus_rafs::RafsError;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeError;
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

pub mod daemon;
mod fs_service;
mod fusedev;
mod singleton;
pub mod upgrade;

pub use blob_cache::{BlobCacheMgr, BlobCacheObjectInfo, BlobCacheObjectList};
pub use fs_service::{FsBackendCollection, FsBackendMountCmd, FsBackendUmountCmd, FsService};
pub use fusedev::{FusedevDaemon, create_fuse_daemon, create_vfs_backend};
pub use singleton::ServiceController;
pub use singleton::create_daemon;

#[cfg(target_os = "linux")]
pub mod blob_cache;
#[cfg(all(target_os = "linux", feature = "block-device"))]
pub mod block_device;
#[cfg(all(target_os = "linux", feature = "block-nbd"))]
pub mod block_nbd;
#[cfg(all(target_os = "linux", feature = "block-uffd"))]
pub mod block_uffd;
#[cfg(target_os = "linux")]
pub mod fanotify;
#[cfg(target_os = "linux")]
mod fanotify_sys;
#[cfg(all(target_os = "linux", feature = "block-uffd"))]
pub mod uffd_proto;

#[cfg(target_os = "linux")]
pub use fanotify::FanotifyHandler;

/// Error code related to Nydus library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("object or filesystem already exists")]
    AlreadyExists,
    /// Invalid arguments provided.
    #[error("invalid argument `{0}`")]
    InvalidArguments(String),
    #[error("invalid configuration, {0}")]
    InvalidConfig(String),
    #[error("invalid prefetch file list")]
    InvalidPrefetchList,
    #[error("object or filesystem doesn't exist")]
    NotFound,
    /// The request cannot proceed because the object is still in use.
    #[error("object is busy, {0}")]
    Busy(String),
    /// Failed to reclaim a blob's on-disk cache.
    #[error("failed to delete blob cache, {0}")]
    DeleteBlob(String),
    #[error("daemon is not ready yet")]
    NotReady,
    #[error("unsupported request or operation")]
    Unsupported,
    #[error("failed to serialize/deserialize message, {0}")]
    Serde(SerdeError),
    #[error("failed to spawn thread, {0}")]
    ThreadSpawn(io::Error),
    #[error("failed to send message to channel, {0}")]
    ChannelSend(#[from] SendError<crate::daemon::DaemonStateMachineInput>),
    #[error("failed to receive message from channel, {0}")]
    ChannelReceive(#[from] RecvError),
    #[error("failed to upgrade nydusd daemon, {0}")]
    UpgradeManager(upgrade::UpgradeMgrError),
    #[error("failed to start service, {0}")]
    StartService(String),
    /// Input event to stat-machine is not expected.
    #[error("unexpected state machine transition event `{0:?}`")]
    UnexpectedEvent(crate::daemon::DaemonStateMachineInput),
    #[error("failed to wait daemon, {0}")]
    WaitDaemon(#[source] io::Error),

    #[error("filesystem type mismatch, expect {0}")]
    FsTypeMismatch(String),
    #[error("passthroughfs failed to handle request, {0}")]
    PassthroughFs(#[source] io::Error),
    #[error("RAFS failed to handle request, {0}")]
    Rafs(#[from] RafsError),
    #[error("VFS failed to handle request, {0:?}")]
    Vfs(#[from] VfsError),

    // fusedev
    #[error("failed to create FUSE server, {0}")]
    CreateFuseServer(io::Error),
    // Fuse session has been shutdown.
    #[error("FUSE session has been shut down, {0}")]
    SessionShutdown(FuseTransportError),
    #[error("FUSE notify error, {0}")]
    NotifyError(#[from] FuseNotifyError),
    #[error("failed to walk and notify invalidation: {0}")]
    WalkNotifyInvalidation(#[from] std::io::Error),

    // virtio-fs
    #[error("failed to handle event other than input event")]
    HandleEventNotEpollIn,
    #[error("failed to handle unknown event")]
    HandleEventUnknownEvent,
    #[error("fail to walk descriptor chain")]
    IterateQueue,
    #[error("invalid Virtio descriptor chain, {0}")]
    InvalidDescriptorChain(FuseTransportError),
    #[error("failed to process FUSE request, {0}")]
    ProcessQueue(#[from] FuseError),
    #[error("failed to create epoll context, {0}")]
    Epoll(#[source] io::Error),
    #[error("vhost-user failed to process request, {0}")]
    VhostUser(String),
    #[error("missing memory configuration for virtio queue")]
    QueueMemoryUnset,
}

/// Boundary conversion for the FUSE and vhost pins.
///
/// This used to be `einval!(e)`, which threw `e` away and answered `EINVAL` for everything --
/// a full disk, a missing blob and a bad mount option were indistinguishable at the FUSE
/// boundary, and all three arrived as "Invalid argument".
///
/// An errno recovered from anywhere on the chain wins, because it came from a real syscall and
/// the kernel on the other side can act on it (`ENOSPC` must stay `ENOSPC`). Only when there is
/// no errno to recover does the variant pick the kind -- and then the message is kept as the
/// payload, which is what makes the difference visible in a log.
impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        if let Some(errno) = nydus_utils::source_errno(&e) {
            return io::Error::from_raw_os_error(errno);
        }
        let kind = match &e {
            Error::NotFound => io::ErrorKind::NotFound,
            Error::AlreadyExists => io::ErrorKind::AlreadyExists,
            Error::Unsupported => io::ErrorKind::Unsupported,
            Error::Busy(_) => io::ErrorKind::ResourceBusy,
            Error::InvalidArguments(_)
            | Error::InvalidConfig(_)
            | Error::InvalidPrefetchList
            | Error::FsTypeMismatch(_) => io::ErrorKind::InvalidInput,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e)
    }
}

/// Map a daemon error onto the kind the HTTP API reports.
///
/// `DaemonErrorKind`'s `Debug` rendering *is* the wire format (see the note on `HttpError` in
/// `nydus_api::http`), so this deliberately routes only the cases a client can act on
/// differently -- not found, already exists, bad argument -- through their own variants. The
/// rest still collapse into `Other`, which keeps every string a caller might already be
/// matching on unchanged.
impl From<Error> for DaemonErrorKind {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            UpgradeManager(e) => DaemonErrorKind::UpgradeManager(format!("{:?}", e)),
            NotReady => DaemonErrorKind::NotReady,
            Unsupported => DaemonErrorKind::Unsupported,
            Serde(e) => DaemonErrorKind::Serde(e),
            UnexpectedEvent(e) => DaemonErrorKind::UnexpectedEvent(format!("{:?}", e)),
            NotFound => DaemonErrorKind::NotFound,
            AlreadyExists => DaemonErrorKind::AlreadyExists,
            InvalidArguments(msg) => DaemonErrorKind::InvalidArguments(msg),
            InvalidConfig(msg) => DaemonErrorKind::InvalidArguments(msg),
            o => DaemonErrorKind::Other(o.to_string()),
        }
    }
}

/// Specialized `Result` for Nydus library.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum FuseNotifyError {
    #[error("Session failure error, {0}")]
    SessionFailure(#[from] FuseTransportError),
    #[error("Fuse write error, {0}")]
    FuseWriteError(#[source] FuseError),
    #[error("Sysfs file open error, {0}")]
    SysfsOpenError(#[source] io::Error),
    #[error("Sysfs write error, {0}")]
    SysfsWriteError(#[source] io::Error),
}

/// Type of supported backend filesystems.
#[derive(Clone, Debug, Serialize, PartialEq, Deserialize, Versionize)]
pub enum FsBackendType {
    /// Registry Accelerated File System
    Rafs,
    /// Share an underlying directory as a FUSE filesystem.
    PassthroughFs,
}

impl FromStr for FsBackendType {
    type Err = Error;

    fn from_str(s: &str) -> Result<FsBackendType> {
        match s {
            "rafs" => Ok(FsBackendType::Rafs),
            "passthrough" => Ok(FsBackendType::PassthroughFs),
            "passthroughfs" => Ok(FsBackendType::PassthroughFs),
            "passthrough_fs" => Ok(FsBackendType::PassthroughFs),
            o => Err(Error::InvalidArguments(format!(
                "only 'rafs' and 'passthrough_fs' are supported, but {} was specified",
                o
            ))),
        }
    }
}

impl Display for FsBackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Backend filesystem descriptor.
#[derive(Serialize, Clone, Deserialize)]
pub struct FsBackendDescriptor {
    /// Type of backend filesystem.
    pub backend_type: FsBackendType,
    /// Mount point for the filesystem.
    pub mountpoint: String,
    /// Timestamp for the mount operation.
    pub mounted_time: time::OffsetDateTime,
    /// Optional configuration information for the backend filesystem.
    pub config: Option<ConfigV2>,
}

/// Validate thread number configuration, valid range is `[1-1024]`.
pub fn validate_threads_configuration<V: AsRef<str>>(v: V) -> std::result::Result<usize, String> {
    if let Ok(t) = v.as_ref().parse::<usize>() {
        if t > 0 && t <= 1024 {
            Ok(t)
        } else {
            Err(format!(
                "invalid thread number {}, valid range: [1-1024]",
                t
            ))
        }
    } else {
        Err(format!(
            "invalid thread number configuration: {}",
            v.as_ref()
        ))
    }
}

/// Trait to get configuration options for services.
pub trait ServiceArgs {
    /// Get value of commandline option `key`.
    fn value_of(&self, key: &str) -> Option<&String>;

    /// Check whether commandline optio `key` is present.
    fn is_present(&self, key: &str) -> bool;
}

#[cfg(not(target_os = "linux"))]
mod blob_cache {
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    pub struct BlobCacheObjectInfo {
        #[serde(rename = "type")]
        pub blob_type: String,
        pub domain_id: String,
        #[serde(rename = "id")]
        pub blob_id: String,
        pub ref_count: u32,
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
    pub struct BlobCacheObjectList {
        pub blobs: Vec<BlobCacheObjectInfo>,
    }

    pub struct BlobCacheMgr {}

    impl Default for BlobCacheMgr {
        fn default() -> Self {
            Self::new()
        }
    }

    impl BlobCacheMgr {
        pub fn new() -> Self {
            BlobCacheMgr {}
        }

        pub fn add_blob_list(&self, _blobs: &nydus_api::BlobCacheList) -> io::Result<()> {
            unimplemented!()
        }

        pub fn add_blob_entry(&self, _entry: &nydus_api::BlobCacheEntry) -> Result<()> {
            unimplemented!()
        }

        pub fn remove_blob_entry(&self, _param: &nydus_api::BlobCacheObjectId) -> Result<()> {
            unimplemented!()
        }

        pub fn list_blob_entries(
            &self,
            _param: &nydus_api::BlobCacheObjectId,
        ) -> io::Result<BlobCacheObjectList> {
            unimplemented!()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_fs_type() {
        assert_eq!(
            FsBackendType::from_str("rafs").unwrap(),
            FsBackendType::Rafs
        );
        assert_eq!(
            FsBackendType::from_str("passthrough").unwrap(),
            FsBackendType::PassthroughFs
        );
        assert_eq!(
            FsBackendType::from_str("passthroughfs").unwrap(),
            FsBackendType::PassthroughFs
        );
        assert_eq!(
            FsBackendType::from_str("passthrough_fs").unwrap(),
            FsBackendType::PassthroughFs
        );
        assert!(FsBackendType::from_str("passthroug").is_err());

        assert_eq!(format!("{}", FsBackendType::Rafs), "Rafs");
        assert_eq!(format!("{}", FsBackendType::PassthroughFs), "PassthroughFs");
    }

    #[test]
    fn test_backend_fs_type_invalid_inputs() {
        let err = FsBackendType::from_str("").unwrap_err();
        assert!(
            err.to_string()
                .contains("only 'rafs' and 'passthrough_fs' are supported")
        );

        let err = FsBackendType::from_str("Rafs").unwrap_err();
        assert!(err.to_string().contains("Rafs was specified"));
    }

    #[test]
    fn test_validate_thread_configuration() {
        assert_eq!(validate_threads_configuration("1").unwrap(), 1);
        assert_eq!(validate_threads_configuration("1024").unwrap(), 1024);
        assert!(validate_threads_configuration("0").is_err());
        assert!(validate_threads_configuration("-1").is_err());
        assert!(validate_threads_configuration("1.0").is_err());
        assert!(validate_threads_configuration("1025").is_err());
        assert!(validate_threads_configuration("test").is_err());
    }

    /// The FUSE/vhost boundary must stop flattening everything to `EINVAL`.
    #[test]
    fn test_error_into_io_error() {
        let io_err: std::io::Error = Error::NotFound.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);

        let io_err: std::io::Error = Error::InvalidArguments("bad arg".into()).into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            io_err.to_string().contains("bad arg"),
            "the message must survive the conversion: {io_err}"
        );

        let io_err: std::io::Error = Error::AlreadyExists.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::AlreadyExists);
    }

    /// An errno raised by a real syscall deeper down has to reach the kernel unchanged.
    ///
    /// This is the disk-full path: a cache `pwrite` fails with `ENOSPC`, the error travels up
    /// through storage and rafs, and the fanotify handler answers the permission event with
    /// whatever `raw_os_error()` reports. Anything else there means a reader is told "I/O
    /// error" for a full disk -- or, if the event is allowed instead, silently reads zeros.
    #[test]
    fn io_error_conversion_preserves_a_real_errno() {
        let storage = nydus_storage::StorageError::cache_io(
            "pwrite",
            std::io::Error::from_raw_os_error(libc::ENOSPC),
        );
        let e = Error::Rafs(RafsError::from(storage));

        assert_eq!(nydus_utils::source_errno(&e), Some(libc::ENOSPC));
        let io_err: std::io::Error = e.into();
        assert_eq!(io_err.raw_os_error(), Some(libc::ENOSPC));
    }

    #[test]
    fn test_error_to_daemon_error_kind() {
        use nydus_api::DaemonErrorKind;

        // NotReady branch
        let kind = DaemonErrorKind::from(Error::NotReady);
        assert!(matches!(kind, DaemonErrorKind::NotReady));

        // Unsupported branch
        let kind = DaemonErrorKind::from(Error::Unsupported);
        assert!(matches!(kind, DaemonErrorKind::Unsupported));

        // UpgradeManager branch
        let kind = DaemonErrorKind::from(Error::UpgradeManager(
            upgrade::UpgradeMgrError::MissingSupervisorPath,
        ));
        assert!(matches!(kind, DaemonErrorKind::UpgradeManager(_)));

        // Serde branch
        let serde_err = serde_json::from_str::<i32>("invalid_json").unwrap_err();
        let kind = DaemonErrorKind::from(Error::Serde(serde_err));
        assert!(matches!(kind, DaemonErrorKind::Serde(_)));

        // UnexpectedEvent branch
        use crate::daemon::DaemonStateMachineInput;
        let kind = DaemonErrorKind::from(Error::UnexpectedEvent(DaemonStateMachineInput::Start));
        assert!(matches!(kind, DaemonErrorKind::UnexpectedEvent(_)));

        // Cases a client can act on differently now have their own variant.
        let kind = DaemonErrorKind::from(Error::AlreadyExists);
        assert!(matches!(kind, DaemonErrorKind::AlreadyExists));
        let kind = DaemonErrorKind::from(Error::NotFound);
        assert!(matches!(kind, DaemonErrorKind::NotFound));
        let kind = DaemonErrorKind::from(Error::InvalidArguments("bad".into()));
        assert!(matches!(kind, DaemonErrorKind::InvalidArguments(m) if m == "bad"));

        // Everything else still collapses into `Other`, keeping the wire strings stable.
        let kind = DaemonErrorKind::from(Error::InvalidPrefetchList);
        assert!(matches!(kind, DaemonErrorKind::Other(_)));
    }

    #[test]
    fn test_fuse_notify_error_display() {
        let e = FuseNotifyError::SysfsOpenError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no file",
        ));
        assert!(e.to_string().contains("Sysfs file open error"));

        let e = FuseNotifyError::SysfsWriteError(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        assert!(e.to_string().contains("Sysfs write error"));
    }

    #[test]
    fn test_error_display_variants() {
        assert!(Error::AlreadyExists.to_string().contains("already exists"));
        assert!(Error::NotFound.to_string().contains("doesn't exist"));
        assert!(Error::NotReady.to_string().contains("not ready"));
        assert!(Error::Unsupported.to_string().contains("unsupported"));
        assert!(
            Error::InvalidPrefetchList
                .to_string()
                .contains("prefetch file list")
        );
        assert!(
            Error::InvalidConfig("cfg".into())
                .to_string()
                .contains("cfg")
        );
        assert!(
            Error::InvalidArguments("arg".into())
                .to_string()
                .contains("arg")
        );
    }
}
