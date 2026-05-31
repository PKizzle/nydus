// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Online upgrade manager for Nydus daemons and filesystems.

use std::any::TypeId;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::str::FromStr;

use nydus_api::{BlobCacheEntry, ConfigV2};
use nydus_upgrade::backend::unix_domain_socket::UdsStorageBackend;
use nydus_upgrade::backend::{StorageBackend, StorageBackendErr};

use crate::fs_service::{FsBackendMountCmd, FsBackendUmountCmd};
use crate::{Error, Result};
use fuse_backend_rs::api::Vfs;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

/// Error codes related to upgrade manager.
#[derive(thiserror::Error, Debug)]
pub enum UpgradeMgrError {
    #[error("missing supervisor path")]
    MissingSupervisorPath,

    #[error("failed to save/restore data via the backend, {0}")]
    StorageBackendError(StorageBackendErr),
    #[error("failed to serialize, {0}")]
    Serialize(io::Error),
    #[error("failed to deserialize, {0}")]
    Deserialize(io::Error),
    #[error("failed to clone file, {0}")]
    CloneFile(io::Error),
    #[error("failed to initialize fanotify driver, {0}")]
    InitializeFanotify(io::Error),
}

impl From<UpgradeMgrError> for Error {
    fn from(e: UpgradeMgrError) -> Self {
        Error::UpgradeManager(e)
    }
}

/// FUSE fail-over policies.
#[derive(PartialEq, Eq, Debug)]
pub enum FailoverPolicy {
    /// Do nothing.
    None,
    /// Flush pending requests.
    Flush,
    /// Resend pending requests.
    Resend,
}

impl TryFrom<&str> for FailoverPolicy {
    type Error = std::io::Error;

    fn try_from(p: &str) -> std::result::Result<Self, Self::Error> {
        match p {
            "none" => Ok(FailoverPolicy::None),
            "flush" => Ok(FailoverPolicy::Flush),
            "resend" => Ok(FailoverPolicy::Resend),
            x => Err(einval!(format!("invalid FUSE fail-over mode {}", x))),
        }
    }
}

impl TryFrom<&String> for FailoverPolicy {
    type Error = std::io::Error;

    fn try_from(p: &String) -> std::result::Result<Self, Self::Error> {
        p.as_str().try_into()
    }
}

/// Per-handler state needed to rebuild a [`crate::fanotify::FanotifyHandler`] around a fanotify
/// group fd preserved across a hot upgrade. One entry per registered EROFS mount.
#[derive(Clone, Debug)]
struct FanotifyHandlerState {
    image_id: String,
    blob_dir: String,
    mountpoint: String,
    threads: usize,
}

/// State for fanotify pre-content backend (replaces the deprecated fscache backend).
///
/// `blob_entry_map` is the set of blob-cache entries to re-add on takeover; `handlers` records,
/// per mount, where to re-derive device files. The preserved fanotify group fds themselves travel
/// out-of-band as `SCM_RIGHTS` ancillary data (see [`UpgradeManager::fanotify_files`]); the i-th
/// fd corresponds to `handlers[i]`.
struct FanotifyState {
    blob_entry_map: HashMap<String, BlobCacheEntry>,
    handlers: Vec<FanotifyHandlerState>,
}

#[derive(Versionize, Clone, Debug)]
struct MountStateWrapper {
    cmd: FsBackendMountCmd,
    vfs_index: u8,
}

struct FusedevState {
    fs_mount_cmd_map: HashMap<String, MountStateWrapper>,
    vfs_state_data: Vec<u8>,
    fuse_conn_id: u64,
}

fn redact_mount_cmd_secrets(mut cmd: FsBackendMountCmd) -> FsBackendMountCmd {
    if matches!(&cmd.fs_type, crate::FsBackendType::Rafs) {
        if let Ok(config) = ConfigV2::from_str(&cmd.config) {
            match serde_json::to_string(&config.clone_without_secrets()) {
                Ok(redacted) => cmd.config = redacted,
                Err(e) => warn!("failed to redact mount configuration: {}", e),
            }
        }
    }
    cmd
}

/// Online upgrade manager.
pub struct UpgradeManager {
    fanotify_deamon_stat: FanotifyState,
    fuse_deamon_stat: FusedevState,
    file: Option<File>,
    /// Fanotify group fds preserved across a hot upgrade, in the same order as
    /// `fanotify_deamon_stat.handlers`. Held only between `save()` and process exit (the predecessor)
    /// or between `restore()` and handler reconstruction (the successor).
    fanotify_files: Vec<File>,
    backend: Box<dyn StorageBackend>,
}

impl UpgradeManager {
    /// Create a new instance of [UpgradeManager].
    pub fn new(socket_path: PathBuf) -> Self {
        UpgradeManager {
            fanotify_deamon_stat: FanotifyState {
                blob_entry_map: HashMap::new(),
                handlers: Vec::new(),
            },
            fuse_deamon_stat: FusedevState {
                fs_mount_cmd_map: HashMap::new(),
                vfs_state_data: vec![],
                fuse_conn_id: 0,
            },
            file: None,
            fanotify_files: Vec::new(),
            backend: Box::new(UdsStorageBackend::new(socket_path)),
        }
    }
    pub fn add_blob_entry_state(&mut self, entry: BlobCacheEntry) {
        let mut blob_state_id = entry.domain_id.to_string();
        blob_state_id.push('/');
        blob_state_id.push_str(&entry.blob_id);

        self.fanotify_deamon_stat
            .blob_entry_map
            .insert(blob_state_id, entry.clone_without_secrets());
    }

    pub fn remove_blob_entry_state(&mut self, domain_id: &str, blob_id: &str) {
        let mut blob_state_id = domain_id.to_string();
        blob_state_id.push('/');
        // for no shared domain mode, snapshotter will call unbind without blob_id
        if !blob_id.is_empty() {
            blob_state_id.push_str(blob_id);
        } else {
            blob_state_id.push_str(domain_id);
        }

        if self
            .fanotify_deamon_stat
            .blob_entry_map
            .remove(&blob_state_id)
            .is_none()
        {
            warn!("blob {}: state was not saved before!", blob_state_id)
        }
    }

    /// Persist fanotify daemon state plus the preserved group fds to the upgrade backend.
    ///
    /// `files` are dup'd fanotify group fds (one per handler, in `handlers` order); they are kept
    /// alive in `self.fanotify_files` until the backend has transferred them via `SCM_RIGHTS`.
    fn save_fanotify(&mut self, files: Vec<File>, data: &[u8]) -> Result<()> {
        self.fanotify_files = files;
        let fds: Vec<RawFd> = self.fanotify_files.iter().map(|f| f.as_raw_fd()).collect();
        self.backend
            .save(&fds, data)
            .map_err(UpgradeMgrError::StorageBackendError)?;
        Ok(())
    }

    /// Restore the preserved fanotify group fds and serialized daemon state from the backend.
    ///
    /// Returns the fds (as owning `File`s, in `handlers` order) and the serialized state blob.
    fn restore_fanotify(&mut self) -> Result<(Vec<File>, Vec<u8>)> {
        let (fds, state_data) = self
            .backend
            .restore()
            .map_err(UpgradeMgrError::StorageBackendError)?;
        let files = fds
            .into_iter()
            .map(|fd| unsafe { File::from_raw_fd(fd) })
            .collect();
        Ok((files, state_data))
    }

    pub fn save_fuse_cid(&mut self, fuse_conn_id: u64) {
        self.fuse_deamon_stat.fuse_conn_id = fuse_conn_id;
    }

    pub fn save_vfs_stat(&mut self, vfs: &Vfs) -> Result<()> {
        let vfs_state_data = vfs.save_to_bytes().map_err(|e| {
            let io_err = io::Error::other(format!("Failed to save vfs state: {:?}", e));
            UpgradeMgrError::Serialize(io_err)
        })?;
        self.fuse_deamon_stat.vfs_state_data = vfs_state_data;
        Ok(())
    }

    /// Add a filesystem instance into the upgrade manager.
    pub fn add_mounts_state(&mut self, cmd: FsBackendMountCmd, vfs_index: u8) {
        let cmd_wrapper = MountStateWrapper {
            cmd: redact_mount_cmd_secrets(cmd.clone()),
            vfs_index,
        };
        self.fuse_deamon_stat
            .fs_mount_cmd_map
            .insert(cmd.mountpoint, cmd_wrapper);
    }

    /// Update a filesystem instance in the upgrade manager.
    pub fn update_mounts_state(&mut self, cmd: FsBackendMountCmd) -> Result<()> {
        match self
            .fuse_deamon_stat
            .fs_mount_cmd_map
            .get_mut(&cmd.mountpoint)
        {
            Some(cmd_wrapper) => {
                cmd_wrapper.cmd = redact_mount_cmd_secrets(cmd);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Remove a filesystem instance from the upgrade manager.
    pub fn remove_mounts_state(&mut self, cmd: FsBackendUmountCmd) {
        if self
            .fuse_deamon_stat
            .fs_mount_cmd_map
            .remove(&cmd.mountpoint)
            .is_none()
        {
            warn!(
                "mount state for {}: state was not saved before!",
                cmd.mountpoint
            )
        }
    }

    /// Save the fd and daemon state data for online upgrade.
    fn save(&mut self, data: &[u8]) -> Result<()> {
        let mut fds = Vec::new();
        if let Some(ref f) = self.file {
            fds.push(f.as_raw_fd())
        }

        self.backend
            .save(&fds, data)
            .map_err(UpgradeMgrError::StorageBackendError)?;
        Ok(())
    }

    /// Restore the fd and daemon state data for online upgrade.
    fn restore(&mut self) -> Result<Vec<u8>> {
        let (fds, state_data) = self
            .backend
            .restore()
            .map_err(UpgradeMgrError::StorageBackendError)?;
        if fds.len() != 1 {
            warn!("Too many fds {}, we may not correctly handle it", fds.len());
        }
        self.file = Some(unsafe { File::from_raw_fd(fds[0]) });
        Ok(state_data)
    }

    pub fn hold_file(&mut self, fd: &File) -> Result<()> {
        let f = fd.try_clone().map_err(UpgradeMgrError::CloneFile)?;
        self.file = Some(f);

        Ok(())
    }

    pub fn return_file(&mut self) -> Option<File> {
        if let Some(ref f) = self.file {
            // Basically, this can hardly fail.
            f.try_clone()
                .map_err(|e| {
                    error!("Clone file error, {}", e);
                    e
                })
                .ok()
        } else {
            warn!("No file can be returned");
            None
        }
    }
}
#[cfg(target_os = "linux")]
/// Online upgrade utilities for fanotify daemon.
pub mod fanotify_upgrade {
    use std::convert::TryFrom;
    use std::str::FromStr;

    use super::*;
    use crate::daemon::NydusDaemon;
    use crate::singleton::ServiceController;
    use nydus_upgrade::persist::Snapshotter;
    use versionize::{VersionMap, Versionize, VersionizeResult};
    use versionize_derive::Versionize;

    #[derive(Versionize, Clone, Debug)]
    pub struct BlobCacheEntryState {
        json_str: String,
    }

    /// Versionize mirror of [`FanotifyHandlerState`] for the upgrade backend.
    #[derive(Versionize, Clone, Default, Debug)]
    pub struct FanotifyHandlerStateV {
        image_id: String,
        blob_dir: String,
        mountpoint: String,
        threads: usize,
    }

    #[derive(Versionize, Clone, Default, Debug)]
    pub struct FanotifyBackendState {
        blob_entry_list: Vec<(String, BlobCacheEntryState)>,
        handlers: Vec<FanotifyHandlerStateV>,
    }

    impl Snapshotter for FanotifyBackendState {
        fn get_versions() -> Vec<HashMap<TypeId, u16>> {
            vec![
                // version 1
                HashMap::from([(FanotifyBackendState::type_id(), 1)]),
                // more versions for the future
            ]
        }
    }

    impl TryFrom<&FanotifyBackendState> for FanotifyState {
        type Error = std::io::Error;
        fn try_from(backend_stat: &FanotifyBackendState) -> std::result::Result<Self, Self::Error> {
            let mut map = HashMap::new();
            for (id, entry_stat) in &backend_stat.blob_entry_list {
                let entry = BlobCacheEntry::from_str(&entry_stat.json_str)?;
                map.insert(id.to_string(), entry);
            }
            let handlers = backend_stat
                .handlers
                .iter()
                .map(|h| FanotifyHandlerState {
                    image_id: h.image_id.clone(),
                    blob_dir: h.blob_dir.clone(),
                    mountpoint: h.mountpoint.clone(),
                    threads: h.threads,
                })
                .collect();
            Ok(FanotifyState {
                blob_entry_map: map,
                handlers,
            })
        }
    }

    impl TryFrom<&FanotifyState> for FanotifyBackendState {
        type Error = std::io::Error;
        fn try_from(stat: &FanotifyState) -> std::result::Result<Self, Self::Error> {
            let mut list = Vec::new();
            for (id, entry) in &stat.blob_entry_map {
                let entry_stat = serde_json::to_string(&entry)?;
                list.push((
                    id.to_string(),
                    BlobCacheEntryState {
                        json_str: entry_stat,
                    },
                ));
            }
            let handlers = stat
                .handlers
                .iter()
                .map(|h| FanotifyHandlerStateV {
                    image_id: h.image_id.clone(),
                    blob_dir: h.blob_dir.clone(),
                    mountpoint: h.mountpoint.clone(),
                    threads: h.threads,
                })
                .collect();
            Ok(FanotifyBackendState {
                blob_entry_list: list,
                handlers,
            })
        }
    }

    /// Save fanotify daemon state for a hot upgrade.
    ///
    /// Snapshots the live handlers (image_id, blob_dir, mountpoint, threads) and hands their
    /// fanotify group fds — which carry the live `FAN_PRE_ACCESS` marks — to the successor via the
    /// upgrade backend's `SCM_RIGHTS` channel. The EROFS mounts stay up throughout, so workloads
    /// keep reading while the daemon is replaced.
    pub fn save(daemon: &ServiceController) -> Result<()> {
        if let Some(mut mgr) = daemon.upgrade_mgr() {
            // Snapshot live handlers + dup'd group fds in a single, consistent order.
            let live = daemon
                .collect_fanotify_upgrade_state()
                .map_err(UpgradeMgrError::CloneFile)?;
            let mut handlers = Vec::with_capacity(live.len());
            let mut files = Vec::with_capacity(live.len());
            for (image_id, blob_dir, mountpoint, threads, file) in live {
                handlers.push(FanotifyHandlerState {
                    image_id,
                    blob_dir,
                    mountpoint,
                    threads,
                });
                files.push(file);
            }
            mgr.fanotify_deamon_stat.handlers = handlers;

            let backend_stat = FanotifyBackendState::try_from(&mgr.fanotify_deamon_stat)
                .map_err(UpgradeMgrError::Serialize)?;
            let stat = backend_stat.save().map_err(UpgradeMgrError::Serialize)?;
            mgr.save_fanotify(files, &stat)?;
        }
        Ok(())
    }

    /// Restore fanotify daemon state after a hot upgrade / takeover.
    ///
    /// Re-adds the blob-cache entries, then rebuilds every handler around its preserved fanotify fd
    /// (no re-arm, no re-mount — the marks and mount survived) and starts its workers, so the new
    /// daemon resumes serving the still-mounted EROFS filesystems.
    pub fn restore(daemon: &ServiceController) -> Result<()> {
        if let Some(mut mgr) = daemon.upgrade_mgr() {
            if let Some(blob_mgr) = daemon.get_blob_cache_mgr() {
                // restore the preserved fds + serialized state via the backend in the mgr
                let (files, mut state_data) = mgr.restore_fanotify()?;

                let backend_stat = FanotifyBackendState::restore(&mut state_data)
                    .map_err(UpgradeMgrError::Deserialize)?;

                let stat =
                    FanotifyState::try_from(&backend_stat).map_err(UpgradeMgrError::Deserialize)?;

                // Re-add blob entries first so handler reconstruction sees a populated cache.
                stat.blob_entry_map
                    .iter()
                    .try_for_each(|(_, entry)| -> Result<()> {
                        blob_mgr
                            .add_blob_entry(entry)
                            .map_err(UpgradeMgrError::Deserialize)?;
                        Ok(())
                    })?;

                if files.len() != stat.handlers.len() {
                    warn!(
                        "fanotify upgrade: {} preserved fds but {} handler records; reconstructing the overlap only",
                        files.len(),
                        stat.handlers.len()
                    );
                }

                // Rebuild each handler from its preserved group fd (fds[i] <-> handlers[i]).
                for (desc, file) in stat.handlers.iter().zip(files) {
                    daemon
                        .restore_fanotify_handler(
                            &desc.image_id,
                            &desc.blob_dir,
                            &desc.mountpoint,
                            desc.threads,
                            file,
                        )
                        .map_err(UpgradeMgrError::InitializeFanotify)?;
                }

                // Restore upgrade manager state
                mgr.fanotify_deamon_stat = stat;
                return Ok(());
            }
        }
        Err(UpgradeMgrError::MissingSupervisorPath.into())
    }
}

/// Online upgrade utilities for FUSE daemon.
pub mod fusedev_upgrade {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::daemon::NydusDaemon;
    use crate::fusedev::{FusedevDaemon, FusedevFsService};
    use nydus_upgrade::persist::Snapshotter;
    use versionize::{VersionMap, Versionize, VersionizeResult};
    use versionize_derive::Versionize;

    #[derive(Versionize, Clone, Default, Debug)]
    pub struct FusedevBackendState {
        fs_mount_cmd_list: Vec<(String, MountStateWrapper)>,
        vfs_state_data: Vec<u8>,
        fuse_conn_id: u64,
    }

    impl Snapshotter for FusedevBackendState {
        fn get_versions() -> Vec<HashMap<TypeId, u16>> {
            vec![
                // version 1
                HashMap::from([(FusedevBackendState::type_id(), 1)]),
                // more versions for the future
            ]
        }
    }

    impl From<&FusedevBackendState> for FusedevState {
        fn from(backend_stat: &FusedevBackendState) -> Self {
            let mut map = HashMap::new();
            for (mp, mw) in &backend_stat.fs_mount_cmd_list {
                map.insert(mp.to_string(), mw.clone());
            }
            FusedevState {
                fs_mount_cmd_map: map,
                vfs_state_data: backend_stat.vfs_state_data.clone(),
                fuse_conn_id: backend_stat.fuse_conn_id,
            }
        }
    }

    impl From<&FusedevState> for FusedevBackendState {
        fn from(stat: &FusedevState) -> Self {
            let mut list = Vec::new();
            for (mp, mw) in &stat.fs_mount_cmd_map {
                list.push((mp.to_string(), mw.clone()));
            }
            FusedevBackendState {
                fs_mount_cmd_list: list,
                vfs_state_data: stat.vfs_state_data.clone(),
                fuse_conn_id: stat.fuse_conn_id,
            }
        }
    }

    /// Save state information for a FUSE daemon.
    pub fn save(daemon: &FusedevDaemon) -> Result<()> {
        let svc = daemon.get_default_fs_service().ok_or(Error::NotFound)?;
        let vfs = svc.get_vfs();
        if !vfs.initialized() {
            return Err(Error::NotReady);
        }

        let mut mgr = svc.upgrade_mgr().unwrap();
        mgr.save_vfs_stat(vfs)?;

        let backend_stat = FusedevBackendState::from(&mgr.fuse_deamon_stat);

        let state = backend_stat.save().map_err(UpgradeMgrError::Serialize)?;
        mgr.save(&state)?;

        Ok(())
    }

    /// Restore state information for a FUSE daemon.
    pub fn restore(daemon: &FusedevDaemon) -> Result<()> {
        if daemon.supervisor.is_none() {
            return Err(UpgradeMgrError::MissingSupervisorPath.into());
        }

        let svc = daemon.get_default_fs_service().ok_or(Error::NotFound)?;

        let mut mgr = svc.upgrade_mgr().unwrap();

        // restore the mgr state via the backend in the mgr
        let mut state_data = mgr.restore()?;

        let backend_state =
            FusedevBackendState::restore(&mut state_data).map_err(UpgradeMgrError::Deserialize)?;

        let mut state = FusedevState::from(&backend_state);

        // restore the fuse daemon
        svc.as_any()
            .downcast_ref::<FusedevFsService>()
            .unwrap()
            .conn
            .store(state.fuse_conn_id, Ordering::Release);

        // restore fuse fd
        if let Some(f) = mgr.return_file() {
            let fuse_svc = svc.as_any().downcast_ref::<FusedevFsService>().unwrap();
            fuse_svc.session.lock().unwrap().set_fuse_file(f);

            // drain fuse requests
            if let Err(e) = fuse_svc.drain_fuse_requests() {
                warn!("Failed to drain fuse requests: {}", e);
            }
        }

        // restore vfs
        svc.get_vfs()
            .restore_from_bytes(&mut state.vfs_state_data)?;
        state
            .fs_mount_cmd_map
            .iter()
            .try_for_each(|(_, mount_wrapper)| -> Result<()> {
                svc.restore_mount(&mount_wrapper.cmd, mount_wrapper.vfs_index)?;
                // as we are in upgrade stage and obtain the lock, `unwrap` is safe here
                //mgr.add_mounts_state(cmd.clone(), *vfs_idx);
                Ok(())
            })?;

        //restore upgrade manager fuse stat
        mgr.fuse_deamon_stat = state;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_service::{FsBackendMountCmd, FsBackendUmountCmd};
    #[cfg(target_os = "linux")]
    use crate::upgrade::fanotify_upgrade::FanotifyBackendState;
    use crate::upgrade::fusedev_upgrade::FusedevBackendState;
    use crate::FsBackendType;
    use nydus_upgrade::persist::Snapshotter;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_failover_policy() {
        assert_eq!(
            FailoverPolicy::try_from("none").unwrap(),
            FailoverPolicy::None
        );
        assert_eq!(
            FailoverPolicy::try_from("flush").unwrap(),
            FailoverPolicy::Flush
        );
        assert_eq!(
            FailoverPolicy::try_from("resend").unwrap(),
            FailoverPolicy::Resend
        );

        let strs = vec!["null", "flash", "Resend"];
        for s in strs.clone().into_iter() {
            assert!(FailoverPolicy::try_from(s).is_err());
        }

        let str = String::from("none");
        assert_eq!(
            FailoverPolicy::try_from(&str).unwrap(),
            FailoverPolicy::None
        );
        let str = String::from("flush");
        assert_eq!(
            FailoverPolicy::try_from(&str).unwrap(),
            FailoverPolicy::Flush
        );
        let str = String::from("resend");
        assert_eq!(
            FailoverPolicy::try_from(&str).unwrap(),
            FailoverPolicy::Resend
        );

        let strings: Vec<String> = strs.into_iter().map(|s| s.to_owned()).collect();
        for s in strings.iter() {
            assert!(FailoverPolicy::try_from(s).is_err());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_upgrade_manager_for_fanotify() {
        let mut upgrade_mgr = UpgradeManager::new("dummy_socket".into());

        let content = r#"{
            "type": "bootstrap",
            "id": "blob1",
            "config_v2": {
                "version": 2,
                "id": "cache1",
                "backend": {
                    "type": "localfs",
                    "localfs": { "dir": "/tmp/nydus" }
                },
                "cache": {
                    "type": "fanotify",
                    "fanotify": { "work_dir": "/tmp" }
                },
                "metadata_path": "/tmp/metadata1"
            },
            "domain_id": "domain1"
        }"#;
        let entry: BlobCacheEntry = serde_json::from_str(content).unwrap();
        upgrade_mgr.fanotify_deamon_stat.handlers = vec![FanotifyHandlerState {
            image_id: "_cli".to_string(),
            blob_dir: "/tmp/fanotify_dir".to_string(),
            mountpoint: "/tmp/fanotify_mnt".to_string(),
            threads: 4,
        }];

        upgrade_mgr.add_blob_entry_state(entry);
        assert!(upgrade_mgr
            .fanotify_deamon_stat
            .blob_entry_map
            .contains_key("domain1/blob1"));

        assert!(FanotifyBackendState::try_from(&upgrade_mgr.fanotify_deamon_stat).is_ok());

        let backend_stat =
            FanotifyBackendState::try_from(&upgrade_mgr.fanotify_deamon_stat).unwrap();
        assert!(backend_stat.save().is_ok());
        assert!(FanotifyState::try_from(&backend_stat).is_ok());
        let stat = FanotifyState::try_from(&backend_stat).unwrap();
        assert_eq!(stat.handlers.len(), 1);
        assert_eq!(stat.handlers[0].image_id, "_cli");
        assert_eq!(stat.handlers[0].blob_dir, "/tmp/fanotify_dir");
        assert_eq!(stat.handlers[0].mountpoint, "/tmp/fanotify_mnt");
        assert_eq!(stat.handlers[0].threads, 4);
        assert!(stat.blob_entry_map.contains_key("domain1/blob1"));

        upgrade_mgr.remove_blob_entry_state("domain1", "blob1");
        assert!(!upgrade_mgr
            .fanotify_deamon_stat
            .blob_entry_map
            .contains_key("domain1/blob1"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_upgrade_manager_redacts_fanotify_blob_entry_secrets() {
        let mut upgrade_mgr = UpgradeManager::new("dummy_socket".into());
        let content = r#"{
            "type": "bootstrap",
            "id": "blob1",
            "config_v2": {
                "version": 2,
                "id": "cache1",
                "backend": {
                    "type": "registry",
                    "registry": {
                        "host": "registry.example.com",
                        "repo": "library/test",
                        "auth": "dXNlcjpwYXNz",
                        "registry_token": "bearer-token"
                    }
                },
                "cache": {
                    "type": "filecache",
                    "filecache": {
                        "work_dir": "/tmp"
                    }
                },
                "metadata_path": "/tmp/bootstrap"
            },
            "domain_id": "domain1"
        }"#;
        let entry: BlobCacheEntry = serde_json::from_str(content).unwrap();

        upgrade_mgr.add_blob_entry_state(entry);
        let saved = upgrade_mgr
            .fanotify_deamon_stat
            .blob_entry_map
            .get("domain1/blob1")
            .unwrap();
        let registry = saved
            .blob_config
            .as_ref()
            .unwrap()
            .backend
            .registry
            .as_ref()
            .unwrap();
        assert!(registry.auth.is_none());
        assert!(registry.registry_token.is_none());
    }

    #[test]
    fn test_upgrade_manager_for_fusedev() {
        let mut upgrade_mgr = UpgradeManager::new("dummy_socket".into());

        let config = r#"{
            "version": 2,
            "id": "factory1",
            "backend": {
                "type": "localfs",
                "localfs": {
                    "dir": "/tmp/nydus"
                }
            },
            "cache": {
                "type": "filecache",
                "filecache": {
                    "work_dir": "/tmp/nydus"
                }
            },
            "metadata_path": "/tmp/nydus/bootstrap1"
        }"#;
        let cmd = FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            config: config.to_string(),
            mountpoint: "testmonutount".to_string(),
            source: "testsource".to_string(),
            prefetch_files: Some(vec!["testfile".to_string()]),
        };

        upgrade_mgr.save_fuse_cid(10);
        assert_eq!(upgrade_mgr.fuse_deamon_stat.fuse_conn_id, 10);
        upgrade_mgr.add_mounts_state(cmd.clone(), 5);
        assert!(upgrade_mgr
            .fuse_deamon_stat
            .fs_mount_cmd_map
            .contains_key("testmonutount"));
        assert!(upgrade_mgr.update_mounts_state(cmd).is_ok());

        let backend_stat = FusedevBackendState::from(&upgrade_mgr.fuse_deamon_stat);
        assert!(backend_stat.save().is_ok());

        let stat = FusedevState::from(&backend_stat);
        assert_eq!(stat.fuse_conn_id, upgrade_mgr.fuse_deamon_stat.fuse_conn_id);
        assert!(stat.fs_mount_cmd_map.contains_key("testmonutount"));

        let umount_cmd: FsBackendUmountCmd = FsBackendUmountCmd {
            mountpoint: "testmonutount".to_string(),
        };
        upgrade_mgr.remove_mounts_state(umount_cmd);
        assert!(!upgrade_mgr
            .fuse_deamon_stat
            .fs_mount_cmd_map
            .contains_key("testmonutount"));
    }

    #[test]
    fn test_upgrade_manager_redacts_fusedev_mount_config_secrets() {
        let mut upgrade_mgr = UpgradeManager::new("dummy_socket".into());

        let config = r#"{
            "version": 2,
            "id": "factory1",
            "backend": {
                "type": "registry",
                "registry": {
                    "host": "registry.example.com",
                    "repo": "library/test",
                    "auth": "dXNlcjpwYXNz",
                    "registry_token": "bearer-token"
                }
            },
            "cache": {
                "type": "filecache",
                "filecache": {
                    "work_dir": "/tmp",
                    "encryption_key": "secret-key"
                }
            }
        }"#;
        let cmd = FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            config: config.to_string(),
            mountpoint: "testmount".to_string(),
            source: "testsource".to_string(),
            prefetch_files: None,
        };

        upgrade_mgr.add_mounts_state(cmd, 1);
        let saved = upgrade_mgr
            .fuse_deamon_stat
            .fs_mount_cmd_map
            .get("testmount")
            .unwrap();
        let redacted = ConfigV2::from_str(&saved.cmd.config).unwrap();
        let registry = redacted
            .backend
            .as_ref()
            .unwrap()
            .registry
            .as_ref()
            .unwrap();
        assert!(registry.auth.is_none());
        assert!(registry.registry_token.is_none());
        assert!(redacted
            .cache
            .as_ref()
            .unwrap()
            .file_cache
            .as_ref()
            .unwrap()
            .encryption_key
            .is_empty());
    }

    #[test]
    fn test_upgrade_manager_hold_fd() {
        let mut upgrade_mgr = UpgradeManager::new("dummy_socket".into());

        let temp = TempFile::new().unwrap().into_file();
        assert!(upgrade_mgr.hold_file(&temp).is_ok());
        assert!(upgrade_mgr.return_file().is_some());
    }
}
