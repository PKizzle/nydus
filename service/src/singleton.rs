// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Nydus daemon to host multiple services, including fanotify and fusedev.

use std::any::Any;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::fs::metadata;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard};

use mio::Waker;
use nydus_api::BuildTimeInfo;
use nydus_api::config::BlobCacheList;

use crate::daemon::{
    DaemonState, DaemonStateMachineContext, DaemonStateMachineInput, DaemonStateMachineSubscriber,
    NydusDaemon,
};
use crate::fs_service::FsService;
use crate::upgrade::UpgradeManager;
use crate::{BlobCacheMgr, Error, Result};
#[cfg(target_os = "linux")]
use nydus_storage::cache::{BLOB_DATA_FILE_SUFFIX, BLOB_RAW_FILE_SUFFIX};

#[allow(dead_code)]
pub struct ServiceController {
    bti: BuildTimeInfo,
    id: Option<String>,
    request_sender: Arc<Mutex<Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<Receiver<Result<()>>>,
    state: AtomicI32,
    supervisor: Option<String>,
    waker: Arc<Waker>,

    blob_cache_mgr: Arc<BlobCacheMgr>,
    upgrade_mgr: Option<Mutex<UpgradeManager>>,
    fanotify_enabled: AtomicBool,
    /// Maps image_id -> FanotifyHandler. Supports multiple concurrent fanotify
    /// mounts served by a single daemon (one handler per image).
    #[cfg(target_os = "linux")]
    fanotify: Mutex<HashMap<String, Arc<crate::fanotify::FanotifyHandler>>>,
}

impl ServiceController {
    /// Start all enabled services.
    ///
    /// Fanotify handlers own their full lifecycle (spawn workers + `arm()` +
    /// `mount()`) inside [`register_fanotify_handler`], which is the only place
    /// that inserts into the `fanotify` map: both the CLI path (before the
    /// `Start` event) and the runtime HTTP path. Re-spawning/re-mounting them
    /// here would double the worker count (breaking `FanotifyHandler`'s
    /// `Barrier::new(threads + 1)` on shutdown) and call `mount(2)` twice on the
    /// same target (EBUSY). So this hook must not touch already-registered
    /// handlers.
    fn start_services(&self) -> std::io::Result<()> {
        info!("Starting all Nydus services...");
        Ok(())
    }

    /// Stop all enabled services.
    fn stop_services(&self) {
        info!("Stopping all Nydus services...");

        #[cfg(target_os = "linux")]
        {
            let mut handlers = self.fanotify.lock().unwrap();
            for (image_id, fanotify) in handlers.drain() {
                info!("Stopping fanotify handler for {}", image_id);
                fanotify.stop();
            }
        }
    }

    fn initialize_blob_cache(&self, config: &Option<serde_json::Value>) -> Result<()> {
        // Create blob cache objects configured by the configuration file.
        if let Some(config) = config
            && let Some(config1) = config.as_object()
            && config1.contains_key("blobs")
            && let Ok(v) = serde_json::from_value::<BlobCacheList>(config.clone())
            && let Err(e) = self.blob_cache_mgr.add_blob_list(&v)
        {
            error!("Failed to add blob list: {}", e);
            return Err(e);
        }

        Ok(())
    }
}

/// Snapshot of one live fanotify handler for a hot upgrade:
/// `(image_id, blob_dir, mountpoint, threads, preserved fanotify group fd)`.
#[cfg(target_os = "linux")]
type FanotifyHandlerSnapshot = (String, String, String, usize, std::fs::File);

#[cfg(target_os = "linux")]
impl ServiceController {
    /// Initialize the fanotify-based on-demand service from command-line arguments.
    ///
    /// `blob_dir` must contain a `bootstrap` file and sparse `blob_<sha256>` files
    /// produced by `nydus-image`. `mountpoint` is where the EROFS filesystem will
    /// be mounted. `threads` controls the number of worker threads polling fanotify events.
    pub fn initialize_fanotify_service(
        &self,
        blob_dir: &str,
        mountpoint: &str,
        threads: usize,
    ) -> std::io::Result<()> {
        self.register_fanotify_handler("_cli", blob_dir, mountpoint, threads)
    }

    /// Register a new fanotify handler for an image.
    ///
    /// This creates a `FanotifyHandler`, places fanotify marks on the blob files,
    /// mounts the EROFS filesystem, and starts worker threads.
    /// The `image_id` is used as a unique key to identify this handler.
    pub fn register_fanotify_handler(
        &self,
        image_id: &str,
        blob_dir: &str,
        mountpoint: &str,
        threads: usize,
    ) -> std::io::Result<()> {
        info!(
            "Register fanotify handler for image {} at {} mountpoint {}, {} working threads",
            image_id, blob_dir, mountpoint, threads
        );
        let fanotify = Arc::new(crate::fanotify::FanotifyHandler::new(
            blob_dir,
            mountpoint,
            self.blob_cache_mgr.clone(),
            threads,
        )?);

        // Start worker threads BEFORE mounting. The EROFS mount opens and reads the marked blob
        // (and bootstrap) device files, which raises FAN_OPEN_PERM / FAN_PRE_ACCESS events that
        // must be answered by a draining worker. Mounting first would block `mount(2)` in
        // the kernel waiting for a response that no running thread could provide -> deadlock
        // (the daemon hangs in uninterruptible `D` state and the mount never appears).
        self.spawn_fanotify_workers(image_id, &fanotify);

        // Arm the marks now that workers are draining, then mount. Pre-content events raised by the
        // EROFS reads that follow the mount are served by the workers spawned above.
        fanotify.arm()?;
        fanotify.mount()?;

        let mut handlers = self.fanotify.lock().unwrap();
        handlers.insert(image_id.to_string(), fanotify);
        self.fanotify_enabled.store(true, Ordering::Release);

        Ok(())
    }

    /// Spawn `working_threads()` worker threads to drain events for `fanotify`.
    ///
    /// Shared by the fresh-registration path ([`register_fanotify_handler`]) and the hot-upgrade
    /// reconstruction path ([`restore_fanotify_handler`]). Each worker wakes the daemon's mio loop
    /// on exit so a crashed worker can tear the daemon down.
    fn spawn_fanotify_workers(
        &self,
        image_id: &str,
        fanotify: &Arc<crate::fanotify::FanotifyHandler>,
    ) {
        for _ in 0..fanotify.working_threads() {
            let f2 = fanotify.clone();
            let waker = self.waker.clone();
            let id = image_id.to_string();
            std::thread::spawn(move || {
                if let Err(e) = f2.run_loop() {
                    error!("Failed to run fanotify service loop for {}: {}", id, e);
                }
                if let Err(err) = waker.wake() {
                    error!("fanotify: fail to exit daemon, error: {:?}", err);
                }
            });
        }
    }

    /// Rebuild a fanotify handler from a fanotify group fd preserved across a hot upgrade.
    ///
    /// The marks and EROFS mount survived the daemon swap (the fd kept the group alive), so this
    /// reconstructs the in-memory handler around the inherited fd and starts its workers **without**
    /// re-arming marks or re-mounting. Workers start before insertion so any faults queued during
    /// the daemon gap are drained immediately.
    pub fn restore_fanotify_handler(
        &self,
        image_id: &str,
        blob_dir: &str,
        mountpoint: &str,
        threads: usize,
        fan_file: std::fs::File,
    ) -> std::io::Result<()> {
        info!(
            "Restore fanotify handler for image {} at {} mountpoint {}, {} working threads",
            image_id, blob_dir, mountpoint, threads
        );
        let fanotify = Arc::new(crate::fanotify::FanotifyHandler::from_restored_fd(
            blob_dir,
            mountpoint,
            self.blob_cache_mgr.clone(),
            threads,
            fan_file,
        )?);

        self.spawn_fanotify_workers(image_id, &fanotify);

        let mut handlers = self.fanotify.lock().unwrap();
        handlers.insert(image_id.to_string(), fanotify);
        self.fanotify_enabled.store(true, Ordering::Release);

        Ok(())
    }

    /// Snapshot the live fanotify handlers for a hot upgrade.
    ///
    /// Returns, per handler, the metadata needed to rebuild it plus a dup of its fanotify group fd
    /// (the dup keeps the group, and its marks, alive after this daemon exits and until the
    /// backend transfers it). Order is stable so it lines up with the serialized handler list.
    pub fn collect_fanotify_upgrade_state(&self) -> std::io::Result<Vec<FanotifyHandlerSnapshot>> {
        let handlers = self.fanotify.lock().unwrap();
        let mut out = Vec::with_capacity(handlers.len());
        for (image_id, fanotify) in handlers.iter() {
            let file = fanotify.get_file()?;
            out.push((
                image_id.clone(),
                fanotify.blob_dir().to_string_lossy().into_owned(),
                fanotify.mountpoint().to_string_lossy().into_owned(),
                fanotify.working_threads(),
                file,
            ));
        }
        Ok(out)
    }

    /// Unregister a fanotify handler for an image.
    ///
    /// This stops the worker threads and unmounts the EROFS filesystem.
    ///
    /// The unmount **must** complete before the handler (and with it the fanotify group fd)
    /// is dropped: `fanotify_release()` fail-opens every permission event still queued on the
    /// group, and an `ALLOW` landing on a still-live mount reads unfilled sparse holes as
    /// zeros. So a busy mount is retried rather than warned about once, and the queue is
    /// drained between attempts so whoever is holding the mount can make progress and let go.
    ///
    /// A failed unmount is reported to the caller instead of being swallowed, but the handler is
    /// still removed: its workers have already been stopped and cannot be restarted, so keeping a
    /// dead entry in the map would be worse than reporting the leaked mount.
    pub fn unregister_fanotify_handler(&self, image_id: &str) -> std::io::Result<()> {
        info!("Unregister fanotify handler for image {}", image_id);
        let mut handlers = self.fanotify.lock().unwrap();
        let mut is_empty = handlers.is_empty();
        let mut result = Ok(());
        if let Some(fanotify) = handlers.remove(image_id) {
            is_empty = handlers.is_empty();
            fanotify.stop();
            // Unmount the EROFS filesystem
            let mountpoint = fanotify.mountpoint().to_path_buf();
            drop(handlers); // Release lock before unmounting
            result = Self::umount_fanotify_erofs(&fanotify, &mountpoint);
            // Only now may the handler — and the group fd it owns — drop.
            drop(fanotify);
        }
        if is_empty {
            self.fanotify_enabled.store(false, Ordering::Release);
        }
        result
    }

    /// Unmount a fanotify-backed EROFS mount, retrying while it is busy.
    ///
    /// Bounded at `UMOUNT_MAX_ATTEMPTS` × `UMOUNT_RETRY_INTERVAL` (≈10s). Each retry is
    /// preceded by a deny-drain so a reader blocked on a pre-content event gets an error and
    /// releases its reference instead of pinning the mount for the whole window.
    fn umount_fanotify_erofs(
        fanotify: &crate::fanotify::FanotifyHandler,
        mountpoint: &std::path::Path,
    ) -> std::io::Result<()> {
        /// Attempts before giving up on a busy mount (≈10s at the interval below).
        const UMOUNT_MAX_ATTEMPTS: u32 = 40;
        /// Delay between unmount attempts.
        const UMOUNT_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

        let mnt_cstr = std::ffi::CString::new(mountpoint.as_os_str().as_encoded_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        for attempt in 1..=UMOUNT_MAX_ATTEMPTS {
            let ret = unsafe { libc::umount(mnt_cstr.as_ptr()) };
            if ret == 0 {
                if attempt > 1 {
                    info!(
                        "Unmounted fanotify EROFS at {:?} after {} attempts",
                        mountpoint, attempt
                    );
                }
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            // EINVAL means it is not a mountpoint any more — someone else already
            // unmounted it, which is the outcome we wanted.
            if err.raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            if err.raw_os_error() != Some(libc::EBUSY) || attempt == UMOUNT_MAX_ATTEMPTS {
                error!(
                    "Failed to unmount fanotify EROFS at {:?} after {} attempt(s): {}",
                    mountpoint, attempt, err
                );
                return Err(err);
            }
            // Busy: answer whatever is queued so a blocked reader can error out and
            // drop its reference, then try again.
            fanotify.drain_deny_pending();
            std::thread::sleep(UMOUNT_RETRY_INTERVAL);
        }
        unreachable!("loop returns on the final attempt")
    }
}

impl NydusDaemon for ServiceController {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    fn version(&self) -> BuildTimeInfo {
        self.bti.clone()
    }

    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    fn start(&self) -> Result<()> {
        self.start_services()
            .map_err(|e| Error::StartService(format!("{}", e)))
    }

    fn umount(&self) -> Result<()> {
        self.stop_services();
        Ok(())
    }

    fn wait(&self) -> Result<()> {
        Ok(())
    }

    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    fn save(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            crate::upgrade::fanotify_upgrade::save(self)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }

    fn restore(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            crate::upgrade::fanotify_upgrade::restore(self)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }

    fn upgrade_mgr(&self) -> Option<MutexGuard<'_, UpgradeManager>> {
        self.upgrade_mgr.as_ref().map(|mgr| mgr.lock().unwrap())
    }

    fn get_default_fs_service(&self) -> Option<Arc<dyn FsService>> {
        None
    }

    fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        Some(self.blob_cache_mgr.clone())
    }

    /// Reclaim a blob's on-disk cache.
    ///
    /// Scoped deliberately to blobs that are **not** currently served. Under the fanotify
    /// path's inode invariant the blob's cache file *is* the EROFS device the kernel reads, so
    /// a live mount pins it: "deleting" it while mounted could not free the data and would
    /// leave the mount reading a file nothing refills. Such a request gets `EBUSY` and the
    /// caller is expected to unregister the handler first, which is what the snapshotter's
    /// teardown path does anyway (snapshot removed → instance stopped → cache reclaimed).
    ///
    /// Invalidating the cache of a *live* blob is a different operation with different
    /// correctness requirements — see [`FanotifyHandler::invalidate`], which must revoke the
    /// chunk map before discarding bytes. It is deliberately not reachable from here.
    #[cfg(target_os = "linux")]
    fn delete_blob(&self, blob_id: String) -> Result<()> {
        {
            let handlers = self.fanotify.lock().unwrap();
            if let Some((image_id, _)) = handlers.iter().find(|(_, h)| h.serves_blob(&blob_id)) {
                warn!(
                    "Refusing to delete blob {}: still served by the mount for image {}",
                    blob_id, image_id
                );
                return Err(Error::Busy(format!(
                    "blob {} is in use by image {}; unregister that image first",
                    blob_id, image_id
                )));
            }
        }

        let config = self
            .blob_cache_mgr
            .get_all_data_blobs()
            .into_iter()
            .find(|cfg| cfg.blob_info().blob_id() == blob_id)
            .ok_or(Error::NotFound)?;

        let work_dir = config
            .config_v2()
            .get_cache_config()
            .and_then(|c| c.get_filecache_config())
            .and_then(|c| c.get_work_dir())
            .map_err(|e| {
                Error::DeleteBlob(format!(
                    "cannot locate the cache directory for blob {}: {}",
                    blob_id, e
                ))
            })?;

        // Three files, because the cache layout depends on configuration:
        //   * `<blob>.blob.data` — the cache file in the normal (decompressed) mode, and the
        //     EROFS device on the fanotify path;
        //   * `<blob>.blob.raw` — used instead when the manager caches raw backend data
        //     (`cache_raw_data`); missing otherwise;
        //   * `<blob>.blob.data.chunk_map` — always named after `.blob.data` regardless of
        //     which of the two is in use (see `FileCacheEntry::create_chunk_map`).
        //
        // The data and its chunk map are one unit: leaving the map behind would have a later
        // open believe the (now absent) data is cached. Removing a file that was never created
        // is the desired end state rather than an error, so listing all three is safe.
        let base = format!("{}/{}", work_dir, blob_id);
        let data = format!("{}{}", base, BLOB_DATA_FILE_SUFFIX);
        let mut removed = 0usize;
        for path in [
            format!("{}.chunk_map", data),
            data,
            format!("{}{}", base, BLOB_RAW_FILE_SUFFIX),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                // Already gone is the desired end state, not a failure.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Error::DeleteBlob(format!("cannot remove {}: {}", path, e)));
                }
            }
        }

        info!(
            "Deleted cache for blob {} ({} file(s) removed from {})",
            blob_id, removed, work_dir
        );
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn delete_blob(&self, _blob_id: String) -> Result<()> {
        Err(Error::Unsupported)
    }
}

impl DaemonStateMachineSubscriber for ServiceController {
    fn on_event(&self, event: DaemonStateMachineInput) -> Result<()> {
        self.request_sender
            .lock()
            .unwrap()
            .send(event)
            .map_err(Error::ChannelSend)?;

        self.result_receiver
            .lock()
            .expect("Not expect poisoned lock!")
            .recv()
            .map_err(Error::ChannelReceive)?
    }
}

#[allow(unused)]
fn is_sock_residual(sock: impl AsRef<Path>) -> bool {
    if metadata(&sock).is_ok() {
        return UnixStream::connect(&sock).is_err();
    }

    false
}
/// When nydusd starts, it checks whether a previous nydusd died unexpected by
/// checking whether the API socket exists and the connection can be established.
fn is_crashed(_sock: &impl AsRef<Path>) -> Result<bool> {
    if is_sock_residual(_sock) {
        warn!("A previous daemon crashed! Try to failover later.");
        return Ok(true);
    }
    Ok(false)
}

/// Create and start a Nydus daemon to host fanotify and fusedev services.
#[allow(clippy::too_many_arguments, unused)]
pub fn create_daemon(
    id: Option<String>,
    supervisor: Option<String>,
    fanotify_blob_dir: Option<&str>,
    fanotify_mountpoint: Option<&str>,
    fanotify_threads: Option<&str>,
    config: Option<serde_json::Value>,
    bti: BuildTimeInfo,
    waker: Arc<Waker>,
    api_sock: Option<impl AsRef<Path>>,
    upgrade: bool,
) -> std::io::Result<Arc<dyn NydusDaemon>> {
    let (to_sm, from_client) = channel::<DaemonStateMachineInput>();
    let (to_client, from_sm) = channel::<Result<()>>();
    let upgrade_mgr = supervisor
        .as_ref()
        .map(|s| Mutex::new(UpgradeManager::new(s.to_string().into())));

    let service_controller = ServiceController {
        bti,
        id,
        request_sender: Arc::new(Mutex::new(to_sm)),
        result_receiver: Mutex::new(from_sm),
        state: AtomicI32::new(DaemonState::INIT as i32),
        supervisor,
        waker,

        blob_cache_mgr: Arc::new(BlobCacheMgr::new()),
        upgrade_mgr,
        fanotify_enabled: AtomicBool::new(false),
        #[cfg(target_os = "linux")]
        fanotify: Mutex::new(HashMap::new()),
    };

    service_controller.initialize_blob_cache(&config)?;

    let daemon = Arc::new(service_controller);
    let machine = DaemonStateMachineContext::new(daemon.clone(), from_client, to_client);
    machine.kick_state_machine()?;

    if (api_sock.as_ref().is_some() && !upgrade && !is_crashed(api_sock.as_ref().unwrap())?)
        || api_sock.is_none()
    {
        #[cfg(target_os = "linux")]
        if let (Some(blob_dir), Some(mountpoint)) = (fanotify_blob_dir, fanotify_mountpoint) {
            let threads = if let Some(threads_value) = fanotify_threads {
                crate::validate_threads_configuration(threads_value)
                    .map_err(|err| Error::InvalidArguments(err.to_string()))?
            } else {
                1usize
            };
            daemon.register_fanotify_handler("_cli", blob_dir, mountpoint, threads)?;
        }

        daemon
            .on_event(DaemonStateMachineInput::Mount)
            .map_err(|e| Error::StartService(e.to_string()))?;
        daemon
            .on_event(DaemonStateMachineInput::Start)
            .map_err(|e| Error::StartService(e.to_string()))?;
    }

    Ok(daemon)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {

    use super::*;
    use mio::{Poll, Token};

    fn create_service_controller() -> ServiceController {
        let bti = BuildTimeInfo {
            package_ver: String::from("package_ver"),
            git_commit: String::from("git_commit"),
            build_time: String::from("build_time"),
            profile: String::from("profile"),
            rustc: String::from("rustc"),
        };

        let (to_sm, _) = channel::<DaemonStateMachineInput>();
        let (_, from_sm) = channel::<Result<()>>();

        let poller = Poll::new().expect("Failed to create poller");
        let waker = Waker::new(poller.registry(), Token(1)).expect("Failed to create waker");

        ServiceController {
            bti,
            id: Some(String::from("id")),
            request_sender: Arc::new(Mutex::new(to_sm)),
            result_receiver: Mutex::new(from_sm),
            state: Default::default(),
            supervisor: Some(String::from("supervisor")),
            waker: Arc::new(waker),
            blob_cache_mgr: Arc::new(BlobCacheMgr::new()),
            upgrade_mgr: None,
            fanotify_enabled: AtomicBool::new(false),
            fanotify: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn test_state_and_properties() {
        let service_controller = create_service_controller();

        assert_eq!(service_controller.id(), Some(String::from("id")));
        assert_eq!(
            service_controller.version().git_commit,
            String::from("git_commit")
        );
        assert_eq!(
            service_controller.supervisor(),
            Some(String::from("supervisor"))
        );
        assert!(
            service_controller
                .as_any()
                .downcast_ref::<ServiceController>()
                .is_some()
        );

        assert_eq!(service_controller.get_state(), DaemonState::UNKNOWN);
        service_controller.set_state(DaemonState::READY);
        assert_eq!(service_controller.get_state(), DaemonState::READY);
        service_controller.set_state(DaemonState::RUNNING);
        assert_eq!(service_controller.get_state(), DaemonState::RUNNING);
    }

    #[test]
    fn test_wait_returns_ok() {
        let service_controller = create_service_controller();
        assert!(service_controller.wait().is_ok());
    }

    #[test]
    fn test_upgrade_mgr_is_none() {
        let service_controller = create_service_controller();
        assert!(service_controller.upgrade_mgr().is_none());
    }

    #[test]
    fn test_get_default_fs_service_is_none() {
        let service_controller = create_service_controller();
        assert!(service_controller.get_default_fs_service().is_none());
    }

    #[test]
    fn test_get_blob_cache_mgr_is_some() {
        let service_controller = create_service_controller();
        assert!(service_controller.get_blob_cache_mgr().is_some());
    }

    #[test]
    fn test_umount_returns_ok() {
        let service_controller = create_service_controller();
        // stop_services does nothing when fanotify_enabled=false
        assert!(service_controller.umount().is_ok());
    }
}
