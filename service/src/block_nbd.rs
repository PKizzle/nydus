// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Export a RAFSv6 image as a block device through NBD(Network Block Device) protocol.
//!
//! The [Network Block Device](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md)
//! is a Linux-originated lightweight block access protocol that allows one to export a block device
//! to a client. RAFSv6 images have an block address based encoding, so an RAFSv6 image can be
//! exposed as a block device. The [NbdService] exposes a RAFSv6 image as a block device based on
//! the Linux Network Block Device driver.

use std::any::Any;
use std::fs::{self, OpenOptions};
use std::io::{Error, Result};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use async_broadcast::{InactiveReceiver, Sender, broadcast};
use bytes::{Buf, BufMut};
use compio::buf::{BufResult, IntoInner, IoBuf};
use compio::io::{AsyncRead, AsyncWriteExt};
use compio::net::UnixStream;
use futures_util::{FutureExt, select};
use mio::Waker;
use nydus_api::{BlobCacheEntry, BuildTimeInfo};
use nydus_storage::utils::alloc_buf;

use crate::blob_cache::{BlobCacheMgr, generate_blob_key};
use crate::block_device::BlockDevice;
use crate::daemon::{
    DaemonState, DaemonStateMachineContext, DaemonStateMachineInput, DaemonStateMachineSubscriber,
    NydusDaemon,
};
use crate::{Error as NydusError, Result as NydusResult};

const NBD_SET_SOCK: u32 = 0;
const NBD_SET_BLOCK_SIZE: u32 = 1;
const NBD_DO_IT: u32 = 3;
const NBD_CLEAR_SOCK: u32 = 4;
const NBD_SET_BLOCKS: u32 = 7;
//const NBD_DISCONNECT: u32 = 8;
const NBD_SET_TIMEOUT: u32 = 9;
const NBD_SET_FLAGS: u32 = 10;
const NBD_FLAG_HAS_FLAGS: u32 = 0x1;
const NBD_FLAG_READ_ONLY: u32 = 0x2;
const NBD_FLAG_CAN_MULTI_CONN: u32 = 0x100;
const NBD_CMD_READ: u32 = 0;
const NBD_CMD_DISC: u32 = 2;
const NBD_REQUEST_HEADER_SIZE: usize = 28;
const NBD_REQUEST_MAGIC: u32 = 0x25609513;
const NBD_REPLY_MAGIC: u32 = 0x67446698;
const NBD_OK: u32 = 0;
const NBD_EIO: u32 = 5;
const NBD_EINVAL: u32 = 22;

fn nbd_ioctl(fd: RawFd, cmd: u32, arg: u64) -> nix::Result<libc::c_int> {
    // `_IO(0xab, cmd)`: direction NONE and size 0, so the request code reduces
    // to `(type << _IOC_NRBITS) | nr` == `(0xab << 8) | cmd`. nix 0.31 dropped
    // the `request_code_none!`/`convert_ioctl_res!` macros, so compute the code
    // directly and map the result through `Errno::result`. `libc::ioctl`'s
    // request parameter is `libc::Ioctl`, which is `c_ulong` on linux-gnu but
    // `c_int` on linux-musl/android — `as _` lets the compiler pick the right
    // width per target so the musl static-release builds stop tripping E0308.
    let code = (0xab_u32 << 8) | cmd;
    nix::errno::Errno::result(unsafe { libc::ioctl(fd, code as _, arg) })
}

/// Network Block Device server to expose RAFSv6 images as block devices.
pub struct NbdService {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    nbd_dev: fs::File,
    sender: Arc<Sender<u32>>,
    // Keepalive for the shutdown broadcast channel. An `async-broadcast` channel
    // closes as soon as its last receiver is dropped, after which `new_receiver()`
    // yields a receiver whose `recv()` returns `Closed` immediately. Workers
    // subscribe lazily via `new_receiver()`, so this inactive receiver pins the
    // channel open without consuming messages; it is never read.
    _shutdown_keepalive: InactiveReceiver<u32>,
}

impl NbdService {
    /// Create a new instance of [NbdService] to expose a RAFSv6 image as a block device.
    ///
    /// It opens the NBD device at `nbd_path` and initialize it according to information from
    /// the block device composed from a RAFSv6 image. The caller needs to ensure that the NBD
    /// device is available.
    pub fn new(device: Arc<BlockDevice>, nbd_path: String) -> Result<Self> {
        // Initialize the NBD device: set block size, block count and flags.
        let nbd_dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&nbd_path)
            .inspect_err(|_e| {
                error!("block_nbd: failed to open NBD device {}", nbd_path);
            })?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_BLOCK_SIZE, device.block_size())?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_BLOCKS, device.blocks() as u64)?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_TIMEOUT, 60)?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0)?;
        nbd_ioctl(
            nbd_dev.as_raw_fd(),
            NBD_SET_FLAGS,
            (NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY | NBD_FLAG_CAN_MULTI_CONN) as u64,
        )?;

        // Shutdown notification: a single value broadcast to every worker so
        // they wake from `select!` and re-check `active`. Overflow mode keeps
        // `try_broadcast` non-blocking and infallible even if the (bounded)
        // queue is full or no worker has subscribed yet. Deactivate (rather than
        // drop) the initial receiver so the channel stays open until workers
        // subscribe via `new_receiver()`; dropping the last receiver would close
        // the channel and make every worker exit its loop immediately.
        let (mut sender, receiver) = broadcast(4);
        sender.set_overflow(true);
        let shutdown_keepalive = receiver.deactivate();

        Ok(NbdService {
            active: Arc::new(AtomicBool::new(true)),
            blob_id: device.meta_blob_id().to_string(),
            cache_mgr: device.cache_mgr().clone(),
            nbd_dev,
            sender: Arc::new(sender),
            _shutdown_keepalive: shutdown_keepalive,
        })
    }

    /// Create a [NbdWorker] to run the event loop to handle NBD requests from kernel.
    pub fn create_worker(&self) -> Result<NbdWorker> {
        // Let the NBD driver go.
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair()?;
        nbd_ioctl(
            self.nbd_dev.as_raw_fd(),
            NBD_SET_SOCK,
            sock1.as_raw_fd() as u64,
        )?;

        Ok(NbdWorker {
            active: self.active.clone(),
            blob_id: self.blob_id.clone(),
            cache_mgr: self.cache_mgr.clone(),
            _sock_kern: sock1,
            sock_user: sock2,
            sender: self.sender.clone(),
        })
    }

    /// Run the event loop to handle incoming NBD requests.
    ///
    /// The caller will get blocked until the NBD device get destroyed or `NbdService::stop()` get
    /// called.
    pub fn run(&self) -> Result<()> {
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_DO_IT, 0);
        self.active.store(false, Ordering::Release);
        let _ = self.sender.try_broadcast(1);
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0);

        Ok(())
    }

    /// Shutdown the NBD session and send exit notification to workers.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self.sender.try_broadcast(0);
        //let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_DISCONNECT, 0);
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0);
    }
}

/// A worker to handle NBD requests in asynchronous mode.
pub struct NbdWorker {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    _sock_kern: std::os::unix::net::UnixStream,
    sock_user: std::os::unix::net::UnixStream,
    sender: Arc<Sender<u32>>,
}

impl NbdWorker {
    /// Run the event loop to handle NBD requests from kernel in asynchronous mode.
    pub async fn run(self) {
        let device =
            match BlockDevice::new_with_cache_manager(self.blob_id.clone(), self.cache_mgr.clone())
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "block_nbd: failed to create block device for {}, {}",
                        self.blob_id, e
                    );
                    return;
                }
            };

        // Wrap a *duplicate* of the user-side socket fd in a compio stream. The
        // original `self.sock_user` stays owned by `self` (still used by
        // `handle_request` via `&self`), so compio must not take ownership of the
        // same fd — otherwise both close it on drop and trip the IO-safety
        // double-close abort. The dup is owned solely by `sock`.
        let mut sock = match self.sock_user.try_clone().and_then(UnixStream::from_std) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "block_nbd: failed to wrap user socket for {}, {}",
                    self.blob_id, e
                );
                return;
            }
        };
        let mut receiver = self.sender.new_receiver();
        let mut buf = vec![0u8; NBD_REQUEST_HEADER_SIZE];
        let mut pos = 0;

        while self.active.load(Ordering::Acquire) {
            // Wait for either the next kernel request bytes or a shutdown
            // broadcast. The branch futures borrow `sock`/`receiver`, so resolve
            // them in an inner scope to `Some(read)`/`None` and drop them before
            // touching `sock` again in `handle_request`.
            let read = {
                let read_fut = sock.read(buf.slice(pos..)).fuse();
                let shutdown_fut = receiver.recv().fuse();
                futures_util::pin_mut!(read_fut, shutdown_fut);
                select! {
                    res = read_fut => Some(res),
                    _ = shutdown_fut => None,
                }
            };
            let BufResult(res, s) = match read {
                Some(res) => res,
                None => break,
            };
            match res {
                Err(e) => {
                    warn!(
                        "block_nbd: failed to get request from kernel for {}, {}",
                        self.blob_id, e
                    );
                    break;
                }
                Ok(sz) => {
                    buf = s.into_inner();
                    pos += sz;
                    if pos == NBD_REQUEST_HEADER_SIZE {
                        match self.handle_request(&buf, &mut sock, &device).await {
                            Ok(true) => {}
                            Ok(false) => break,
                            Err(e) => {
                                warn!(
                                    "block_nbd: failed to handle request for {}, {}",
                                    self.blob_id, e
                                );
                                break;
                            }
                        }
                        pos = 0;
                    }
                }
            }
        }
    }

    async fn handle_request(
        &self,
        mut request: &[u8],
        sock: &mut UnixStream,
        device: &BlockDevice,
    ) -> Result<bool> {
        let magic = request.get_u32();
        let ty = request.get_u32();
        let handle = request.get_u64();
        let pos = request.get_u64();
        let len = request.get_u32();

        let block_size = device.block_size();
        let mut code = NBD_OK;
        let mut data_buf = alloc_buf(len as usize);
        if magic != NBD_REQUEST_MAGIC || pos % block_size != 0 || len as u64 % block_size != 0 {
            warn!(
                "block_nbd: invalid request magic 0x{:x}, type {}, pos 0x{:x}, len 0x{:x}",
                magic, ty, pos, len
            );
            code = NBD_EINVAL;
        } else if ty == NBD_CMD_READ {
            let start = (pos / block_size) as u32;
            let count = len / block_size as u32;
            let (res, buf) = device.async_read(start, count, data_buf).await;
            data_buf = buf;
            match res {
                Ok(sz) => {
                    if sz != len as usize {
                        warn!("block_nbd: got 0x{:x} bytes, expect 0x{:x}", sz, len);
                        code = NBD_EIO;
                    }
                }
                Err(e) => {
                    warn!("block_nbd: failed to read data from block device, {}", e);
                    code = NBD_EIO;
                }
            }
        } else if ty == NBD_CMD_DISC {
            return Ok(false);
        }

        let mut reply = Vec::with_capacity(16);
        reply.put_u32(NBD_REPLY_MAGIC);
        reply.put_u32(code);
        reply.put_u64(handle);
        assert_eq!(reply.len(), 16);
        assert_eq!(data_buf.len(), len as usize);
        sock.write_all(reply).await.0?;
        if code == NBD_OK {
            sock.write_all(data_buf).await.0?;
        }

        Ok(true)
    }
}

/// A [NydusDaemon] implementation to expose RAFS v6 images as block devices through NBD.
pub struct NbdDaemon {
    cache_mgr: Arc<BlobCacheMgr>,
    service: Arc<NbdService>,

    bti: BuildTimeInfo,
    id: Option<String>,
    supervisor: Option<String>,

    nbd_threads: u32,
    nbd_control_thread: Mutex<Option<JoinHandle<()>>>,
    nbd_service_threads: Mutex<Vec<JoinHandle<Result<()>>>>,
    request_sender: Arc<Mutex<std::sync::mpsc::Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<std::sync::mpsc::Receiver<NydusResult<()>>>,
    state: AtomicI32,
    state_machine_thread: Mutex<Option<JoinHandle<Result<()>>>>,
    waker: Arc<Waker>,
}

impl NbdDaemon {
    #[allow(clippy::too_many_arguments)]
    fn new(
        nbd_path: String,
        threads: u32,
        blob_entry: BlobCacheEntry,
        trigger: std::sync::mpsc::Sender<DaemonStateMachineInput>,
        receiver: std::sync::mpsc::Receiver<NydusResult<()>>,
        waker: Arc<Waker>,
        bti: BuildTimeInfo,
        id: Option<String>,
        supervisor: Option<String>,
    ) -> Result<Self> {
        let blob_id = generate_blob_key(&blob_entry.domain_id, &blob_entry.blob_id);
        let cache_mgr = Arc::new(BlobCacheMgr::new());
        cache_mgr.add_blob_entry(&blob_entry)?;
        // `BlockDevice::new_with_cache_manager` opens blob files via compio and
        // is async; run it to completion on a transient compio runtime since
        // this daemon constructor is synchronous.
        let block_device = compio::runtime::Runtime::new().unwrap().block_on(
            BlockDevice::new_with_cache_manager(blob_id.clone(), cache_mgr.clone()),
        )?;
        #[allow(clippy::arc_with_non_send_sync)]
        let nbd_service = NbdService::new(Arc::new(block_device), nbd_path)?;

        Ok(NbdDaemon {
            cache_mgr,
            service: Arc::new(nbd_service),

            bti,
            id,
            supervisor,

            nbd_threads: threads,
            nbd_control_thread: Mutex::new(None),
            nbd_service_threads: Mutex::new(Vec::new()),
            state: AtomicI32::new(DaemonState::INIT as i32),
            request_sender: Arc::new(Mutex::new(trigger)),
            result_receiver: Mutex::new(receiver),
            state_machine_thread: Mutex::new(None),
            waker,
        })
    }
}

impl DaemonStateMachineSubscriber for NbdDaemon {
    fn on_event(&self, event: DaemonStateMachineInput) -> NydusResult<()> {
        self.request_sender
            .lock()
            .expect("block_nbd: failed to lock request sender!")
            .send(event)
            .map_err(NydusError::ChannelSend)?;

        self.result_receiver
            .lock()
            .expect("block_nbd: failed to lock result receiver!")
            .recv()
            .map_err(NydusError::ChannelReceive)?
    }
}

impl NydusDaemon for NbdDaemon {
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

    fn start(&self) -> NydusResult<()> {
        info!("start NBD service with {} worker threads", self.nbd_threads);
        for _ in 0..self.nbd_threads {
            let waker = self.waker.clone();
            let worker = self
                .service
                .create_worker()
                .map_err(|e| NydusError::StartService(format!("{}", e)))?;
            let thread = std::thread::Builder::new()
                .name("nbd_worker".to_string())
                .spawn(move || {
                    compio::runtime::Runtime::new()
                        .unwrap()
                        .block_on(async move {
                            worker.run().await;
                            // Notify the daemon controller that one working thread has exited.
                            if let Err(err) = waker.wake() {
                                error!("block_nbd: fail to exit daemon, error: {:?}", err);
                            }
                        });
                    Ok(())
                })
                .map_err(NydusError::ThreadSpawn)?;
            self.nbd_service_threads.lock().unwrap().push(thread);
        }

        let nbd = self.service.clone();
        let thread = std::thread::spawn(move || {
            if let Err(e) = nbd.run() {
                error!("block_nbd: failed to run NBD control loop, {e}");
            }
        });
        *self.nbd_control_thread.lock().unwrap() = Some(thread);

        Ok(())
    }

    fn umount(&self) -> NydusResult<()> {
        Ok(())
    }

    fn stop(&self) {
        self.service.stop();
    }

    fn wait(&self) -> NydusResult<()> {
        self.wait_state_machine()?;
        self.wait_service()
    }

    fn wait_service(&self) -> NydusResult<()> {
        loop {
            let handle = self.nbd_service_threads.lock().unwrap().pop();
            if let Some(handle) = handle {
                handle
                    .join()
                    .map_err(|e| {
                        let e = *e
                            .downcast::<Error>()
                            .unwrap_or_else(|e| Box::new(eother!(e)));
                        NydusError::WaitDaemon(e)
                    })?
                    .map_err(NydusError::WaitDaemon)?;
            } else {
                // No more handles to wait
                break;
            }
        }

        Ok(())
    }

    fn wait_state_machine(&self) -> NydusResult<()> {
        let mut guard = self.state_machine_thread.lock().unwrap();
        if let Some(handler) = guard.take() {
            let result = handler.join().map_err(|e| {
                let e = *e
                    .downcast::<Error>()
                    .unwrap_or_else(|e| Box::new(eother!(e)));
                NydusError::WaitDaemon(e)
            })?;
            result.map_err(NydusError::WaitDaemon)
        } else {
            Ok(())
        }
    }

    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    fn save(&self) -> NydusResult<()> {
        unimplemented!()
    }

    fn restore(&self) -> NydusResult<()> {
        unimplemented!()
    }

    fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        Some(self.cache_mgr.clone())
    }
}

/// Create and start a [NbdDaemon] instance to expose a RAFS v6 image as a block device through NBD.
#[allow(clippy::too_many_arguments)]
pub fn create_nbd_daemon(
    device: String,
    threads: u32,
    blob_entry: BlobCacheEntry,
    bti: BuildTimeInfo,
    id: Option<String>,
    supervisor: Option<String>,
    waker: Arc<Waker>,
) -> Result<Arc<dyn NydusDaemon>> {
    let (trigger, events_rx) = std::sync::mpsc::channel::<DaemonStateMachineInput>();
    let (result_sender, result_receiver) = std::sync::mpsc::channel::<NydusResult<()>>();
    let daemon = NbdDaemon::new(
        device,
        threads,
        blob_entry,
        trigger,
        result_receiver,
        waker,
        bti,
        id,
        supervisor,
    )?;
    let daemon = Arc::new(daemon);
    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
    let machine_thread = machine.kick_state_machine()?;
    *daemon.state_machine_thread.lock().unwrap() = Some(machine_thread);
    daemon
        .on_event(DaemonStateMachineInput::Mount)
        .map_err(|e| eother!(e))?;
    daemon
        .on_event(DaemonStateMachineInput::Start)
        .map_err(|e| eother!(e))?;

    /*
    // TODO: support crash recover and hot-upgrade.
    // Without api socket, nydusd can't do neither live-upgrade nor failover, so the helper
    // finding a victim is not necessary.
    if (api_sock.as_ref().is_some() && !upgrade && !is_crashed(&mnt, api_sock.as_ref().unwrap())?)
        || api_sock.is_none()
    {
        if let Some(cmd) = mount_cmd {
            daemon.service.mount(cmd)?;
        }
        daemon
            .service
            .session
            .lock()
            .unwrap()
            .mount()
            .map_err(|e| eother!(e))?;
        daemon
            .on_event(DaemonStateMachineInput::Mount)
            .map_err(|e| eother!(e))?;
        daemon
            .on_event(DaemonStateMachineInput::Start)
            .map_err(|e| eother!(e))?;
        daemon
            .service
            .conn
            .store(calc_fuse_conn(mnt)?, Ordering::Relaxed);
    }
     */

    Ok(daemon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_cache::{BlobCacheMgr, generate_blob_key};
    use nydus_api::BlobCacheEntry;
    use std::path::PathBuf;
    use std::time::Duration;
    use vmm_sys_util::tempdir::TempDir;

    #[allow(clippy::arc_with_non_send_sync)]
    fn create_block_device(tmpdir: PathBuf) -> Result<Arc<BlockDevice>> {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        let mut dest_path = tmpdir.clone();
        dest_path.push("be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        fs::copy(&source_path, &dest_path).unwrap();

        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");
        let config = r#"
        {
            "type": "bootstrap",
            "id": "rafs-v6",
            "domain_id": "domain2",
            "config_v2": {
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
                "metadata_path": "RAFS_V5"
            }
          }"#;
        let content = config
            .replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap())
            .replace("RAFS_V5", &source_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());

        let mgr = BlobCacheMgr::new();
        mgr.add_blob_entry(&entry).unwrap();
        let blob_id = generate_blob_key(&entry.domain_id, &entry.blob_id);
        assert!(mgr.get_config(&blob_id).is_some());

        // Check existence of data blob referenced by the bootstrap.
        let key = generate_blob_key(
            &entry.domain_id,
            "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef",
        );
        assert!(mgr.get_config(&key).is_some());

        let mgr = Arc::new(mgr);
        let device = compio::runtime::Runtime::new()
            .unwrap()
            .block_on(BlockDevice::new_with_cache_manager(blob_id.clone(), mgr))
            .unwrap();

        Ok(Arc::new(device))
    }

    // Regression: NbdService::new builds its shutdown broadcast with
    // `broadcast(4)` + `set_overflow(true)` + `receiver.deactivate()`. If that
    // `deactivate()` were a `drop()` (as it was before the async-broadcast
    // migration fix), the channel would close and `NbdWorker::run`'s lazily
    // subscribed `new_receiver().recv()` would return `Closed` immediately,
    // exiting every worker at startup (daemon up, serves nothing) — the exact
    // bug fixed in `block_uffd.rs`. Assert the channel stays open and still
    // delivers the stop signal.
    #[test]
    fn test_nbd_shutdown_channel_stays_open() {
        let (mut sender, receiver) = broadcast::<u32>(4);
        sender.set_overflow(true);
        let _keepalive = receiver.deactivate();

        let mut rx = sender.new_receiver();
        assert_eq!(
            rx.try_recv(),
            Err(async_broadcast::TryRecvError::Empty),
            "a worker subscribing after construction must wait for the stop \
             signal, not observe a closed channel and exit immediately",
        );
        let _ = sender.try_broadcast(0);
        assert_eq!(rx.try_recv(), Ok(0), "stop signal must reach the worker");
    }

    // The real `NbdWorker::run` event loop must wake from its `select!` and exit
    // when the shutdown broadcast fires (rather than hang on the idle kernel
    // socket). Construct a worker directly over a socketpair so no `/dev/nbd*`
    // device is needed.
    #[test]
    fn test_nbd_worker_exits_on_shutdown_broadcast() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let (sock_kern, sock_user) = std::os::unix::net::UnixStream::pair().unwrap();

            let (mut sender, receiver) = broadcast::<u32>(4);
            sender.set_overflow(true);
            let _keepalive = receiver.deactivate();
            let sender = Arc::new(sender);
            let active = Arc::new(AtomicBool::new(true));

            let worker = NbdWorker {
                active: active.clone(),
                blob_id: device.meta_blob_id().to_string(),
                cache_mgr: device.cache_mgr().clone(),
                _sock_kern: sock_kern,
                sock_user,
                sender: sender.clone(),
            };

            let handle = compio::runtime::spawn(async move { worker.run().await });
            // Let the worker reach its select! loop (blocked on the idle socket).
            compio::runtime::time::sleep(Duration::from_millis(50)).await;
            // Signal shutdown; the worker must wake and exit.
            active.store(false, Ordering::Release);
            let _ = sender.try_broadcast(0);

            let res = compio::runtime::time::timeout(Duration::from_secs(2), handle).await;
            assert!(res.is_ok(), "NbdWorker did not exit on shutdown broadcast");
        })
    }

    #[ignore]
    #[test]
    fn test_nbd_device() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let nbd = NbdService::new(device, "/dev/nbd15".to_string()).unwrap();
            let nbd = Arc::new(nbd);
            let nbd2 = nbd.clone();
            let worker1 = nbd.create_worker().unwrap();
            let worker2 = nbd.create_worker().unwrap();

            compio::runtime::spawn(async move { worker1.run().await }).detach();
            compio::runtime::spawn(async move { worker2.run().await }).detach();
            std::thread::spawn(move || {
                nbd2.run().unwrap();
            });
            compio::runtime::time::sleep(Duration::from_micros(100000)).await;
            nbd.stop();
        })
    }
}
