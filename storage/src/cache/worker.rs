// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::thread;
use std::time::{Duration, SystemTime};

use async_lock::Semaphore;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use nydus_api::PrefetchConfigV2;
use nydus_utils::metrics::{BlobcacheMetrics, Metric};
use nydus_utils::mpmc::Channel;

use crate::cache::{BlobCache, BlobIoRange};

thread_local! {
    /// Per-worker-thread compio runtime. compio is thread-per-core (its
    /// `Runtime` is `!Send`), so each prefetch worker thread owns its own
    /// runtime and drives its event loop with `block_on`. This replaces the
    /// shared tokio runtime (`with_runtime` + `ASYNC_RUNTIME`).
    static WORKER_RUNTIME: compio::runtime::Runtime =
        compio::runtime::Runtime::new().expect("storage: failed to create compio worker runtime");
}

/// Prefetch bandwidth limiter: a governor token bucket (byte-cells) plus its
/// burst capacity. governor rejects `until_n_ready(n)` when `n` exceeds the
/// burst, so callers clamp the requested amount to `burst`.
struct PrefetchLimiter {
    limiter: DefaultDirectRateLimiter,
    burst: u32,
}

/// Configuration information for asynchronous workers.
pub(crate) struct AsyncPrefetchConfig {
    /// Whether or not to enable prefetch.
    pub enable: bool,
    /// Number of working threads.
    pub threads_count: usize,
    /// The amplify batch size to prefetch data from backend.
    pub batch_size: usize,
    /// Network bandwidth for prefetch, in unit of Bytes and Zero means no rate limit is set.
    #[allow(unused)]
    pub bandwidth_limit: u32,
}

impl From<&PrefetchConfigV2> for AsyncPrefetchConfig {
    fn from(p: &PrefetchConfigV2) -> Self {
        AsyncPrefetchConfig {
            enable: p.enable,
            threads_count: p.threads_count,
            batch_size: p.batch_size,
            bandwidth_limit: p.bandwidth_limit,
        }
    }
}

/// Asynchronous service request message.
pub(crate) enum AsyncPrefetchMessage {
    /// Asynchronous blob layer prefetch request with (offset, size) of blob on storage backend.
    BlobPrefetch(Arc<dyn BlobCache>, u64, u64, SystemTime),
    /// Asynchronous file-system layer prefetch request.
    FsPrefetch(Arc<dyn BlobCache>, BlobIoRange, SystemTime),
    #[cfg_attr(not(test), allow(unused))]
    /// Ping for test.
    Ping,
    #[allow(unused)]
    RateLimiter(u64),
}

impl AsyncPrefetchMessage {
    /// Create a new asynchronous filesystem prefetch request message.
    pub fn new_fs_prefetch(blob_cache: Arc<dyn BlobCache>, req: BlobIoRange) -> Self {
        AsyncPrefetchMessage::FsPrefetch(blob_cache, req, SystemTime::now())
    }

    /// Create a new asynchronous blob prefetch request message.
    pub fn new_blob_prefetch(blob_cache: Arc<dyn BlobCache>, offset: u64, size: u64) -> Self {
        AsyncPrefetchMessage::BlobPrefetch(blob_cache, offset, size, SystemTime::now())
    }
}

/// An asynchronous task manager for data prefetching
pub(crate) struct AsyncWorkerMgr {
    metrics: Arc<BlobcacheMetrics>,
    ping_requests: AtomicU32,
    workers: AtomicU32,
    active: AtomicBool,
    begin_timing_once: Once,

    // Limit the total retry times to avoid unnecessary resource consumption.
    retry_times: AtomicI32,

    prefetch_sema: Arc<Semaphore>,
    prefetch_channel: Arc<Channel<AsyncPrefetchMessage>>,
    prefetch_config: Arc<AsyncPrefetchConfig>,
    #[allow(unused)]
    prefetch_delayed: AtomicU64,
    prefetch_inflight: AtomicU32,
    prefetch_consumed: AtomicUsize,
    prefetch_limiter: Option<Arc<PrefetchLimiter>>,
}

impl AsyncWorkerMgr {
    /// Create a new instance of `AsyncWorkerMgr`.
    pub fn new(
        metrics: Arc<BlobcacheMetrics>,
        prefetch_config: Arc<AsyncPrefetchConfig>,
    ) -> Result<Self> {
        let prefetch_limiter = match prefetch_config.bandwidth_limit {
            0 => None,
            v => {
                // If the given value is less than maximum blob chunk size, it exceeds burst size of the
                // limiter ending up with throttling all throughput, so ensure bandwidth is bigger than
                // the maximum chunk size.
                // Port the old leaky-bucket config onto a governor token bucket of
                // byte-cells: rate == bucket capacity == `limit` bytes/s, starting
                // full. This mirrors leaky-bucket's `refill(limit/10 per 100ms)` ==
                // `limit`/s with `initial(limit)` (its balance was capped at the
                // initial). governor starts the bucket full, matching `initial`.
                let limit = std::cmp::max(crate::RAFS_MAX_CHUNK_SIZE as usize, v as usize);
                let limit = limit.min(u32::MAX as usize) as u32;
                // SAFETY: limit >= RAFS_MAX_CHUNK_SIZE > 0.
                let quota = Quota::per_second(NonZeroU32::new(limit).unwrap());
                Some(Arc::new(PrefetchLimiter {
                    limiter: RateLimiter::direct(quota),
                    burst: limit,
                }))
            }
        };

        Ok(AsyncWorkerMgr {
            metrics,
            ping_requests: AtomicU32::new(0),
            workers: AtomicU32::new(0),
            active: AtomicBool::new(false),
            begin_timing_once: Once::new(),

            retry_times: AtomicI32::new(32),

            prefetch_sema: Arc::new(Semaphore::new(0)),
            prefetch_channel: Arc::new(Channel::new()),
            prefetch_config,
            prefetch_delayed: AtomicU64::new(0),
            prefetch_inflight: AtomicU32::new(0),
            prefetch_consumed: AtomicUsize::new(0),
            prefetch_limiter,
        })
    }

    /// Create working threads and start the event loop.
    pub fn start(mgr: Arc<AsyncWorkerMgr>) -> Result<()> {
        if mgr.prefetch_config.enable {
            Self::start_prefetch_workers(mgr)?;
        }

        Ok(())
    }

    /// Stop all working threads.
    pub fn stop(&self) {
        if self
            .active
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.prefetch_channel.close();

        while self.workers.load(Ordering::Relaxed) > 0 {
            self.prefetch_channel.notify_waiters();
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Send an asynchronous service request message to the workers.
    pub fn send_prefetch_message(
        &self,
        msg: AsyncPrefetchMessage,
    ) -> std::result::Result<(), AsyncPrefetchMessage> {
        if !self.prefetch_config.enable {
            Err(msg)
        } else {
            self.prefetch_inflight.fetch_add(1, Ordering::Relaxed);
            self.prefetch_channel.send(msg)
        }
    }

    /// Flush pending prefetch requests associated with `blob_id`.
    pub fn flush_pending_prefetch_requests(&self, blob_id: &str) {
        self.prefetch_channel
            .flush_pending_prefetch_requests(|t| match t {
                AsyncPrefetchMessage::BlobPrefetch(blob, _, _, _) => {
                    blob_id == blob.blob_id() && !blob.is_prefetch_active()
                }
                AsyncPrefetchMessage::FsPrefetch(blob, _, _) => {
                    blob_id == blob.blob_id() && !blob.is_prefetch_active()
                }
                _ => false,
            });
    }

    /// Consume network bandwidth budget for prefetching.
    pub fn consume_prefetch_budget(&self, size: u64) {
        if self.prefetch_inflight.load(Ordering::Relaxed) > 0 {
            self.prefetch_consumed
                .fetch_add(size as usize, Ordering::AcqRel);
        }
    }

    fn start_prefetch_workers(mgr: Arc<AsyncWorkerMgr>) -> Result<()> {
        // Hold the request queue to barrier all working threads.
        let guard = mgr.prefetch_channel.lock_channel();
        for num in 0..mgr.prefetch_config.threads_count {
            let mgr2 = mgr.clone();
            let res = thread::Builder::new()
                .name(format!("nydus_storage_worker_{}", num))
                .spawn(move || {
                    mgr2.grow_n(1);
                    mgr2.metrics
                        .prefetch_workers
                        .fetch_add(1, Ordering::Relaxed);

                    WORKER_RUNTIME.with(|rt| {
                        rt.block_on(Self::handle_prefetch_requests(mgr2.clone()));
                    });

                    mgr2.metrics
                        .prefetch_workers
                        .fetch_sub(1, Ordering::Relaxed);
                    mgr2.shrink_n(1);
                    info!("storage: worker thread {} exits.", num)
                });

            if let Err(e) = res {
                error!("storage: failed to create worker thread, {:?}", e);
                mgr.prefetch_channel.close();
                drop(guard);
                mgr.stop();
                return Err(e);
            }
        }
        mgr.active.store(true, Ordering::Release);
        Ok(())
    }

    async fn handle_prefetch_requests(mgr: Arc<AsyncWorkerMgr>) {
        mgr.begin_timing_once.call_once(|| {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();

            mgr.metrics.prefetch_begin_time_secs.set(now.as_secs());
            mgr.metrics
                .prefetch_begin_time_millis
                .set(now.subsec_millis() as u64);
        });

        // Max 1 active requests per thread.
        mgr.prefetch_sema.add_permits(1);

        while let Ok(msg) = mgr.prefetch_channel.recv().await {
            mgr.handle_prefetch_rate_limit(&msg).await;
            let mgr2 = mgr.clone();

            match msg {
                AsyncPrefetchMessage::BlobPrefetch(blob_cache, offset, size, begin_time) => {
                    let token = mgr2.prefetch_sema.acquire_arc().await;
                    if blob_cache.is_prefetch_active() {
                        blocking::unblock(move || {
                            let _ = Self::handle_blob_prefetch_request(
                                mgr2.clone(),
                                blob_cache,
                                offset,
                                size,
                                begin_time,
                            );
                            drop(token);
                        })
                        .detach();
                    }
                }
                AsyncPrefetchMessage::FsPrefetch(blob_cache, req, begin_time) => {
                    let token = mgr2.prefetch_sema.acquire_arc().await;

                    if blob_cache.is_prefetch_active() {
                        blocking::unblock(move || {
                            let _ = Self::handle_fs_prefetch_request(
                                mgr2.clone(),
                                blob_cache,
                                req,
                                begin_time,
                            );
                            drop(token)
                        })
                        .detach();
                    }
                }
                AsyncPrefetchMessage::Ping => {
                    let _ = mgr.ping_requests.fetch_add(1, Ordering::Relaxed);
                }
                AsyncPrefetchMessage::RateLimiter(_size) => {}
            }

            mgr.prefetch_inflight.fetch_sub(1, Ordering::Relaxed);
        }
    }

    async fn handle_prefetch_rate_limit(&self, _msg: &AsyncPrefetchMessage) {
        // Allocate network bandwidth budget
        if let Some(limiter) = &self.prefetch_limiter {
            let size = match _msg {
                AsyncPrefetchMessage::BlobPrefetch(blob_cache, _offset, size, _) => {
                    if blob_cache.is_prefetch_active() {
                        *size
                    } else {
                        0
                    }
                }
                AsyncPrefetchMessage::FsPrefetch(blob_cache, req, _) => {
                    if blob_cache.is_prefetch_active() {
                        req.blob_size
                    } else {
                        0
                    }
                }
                AsyncPrefetchMessage::Ping => 0,
                AsyncPrefetchMessage::RateLimiter(size) => *size,
            };

            if size > 0 {
                let size = (self.prefetch_consumed.swap(0, Ordering::AcqRel))
                    .saturating_add(size as usize);
                // Clamp to the burst capacity so governor accepts the request
                // (`until_n_ready` rejects amounts larger than the burst).
                let size = std::cmp::min(size, limiter.burst as usize) as u32;
                if let Some(n) = NonZeroU32::new(size) {
                    // `check_n` consumes the budget if available right now; if not,
                    // the request is delayed, so count it and wait. Either path
                    // consumes `n` byte-cells exactly once.
                    match limiter.limiter.check_n(n) {
                        Ok(Ok(())) => {}
                        _ => {
                            self.prefetch_delayed.fetch_add(1, Ordering::Relaxed);
                            let _ = limiter.limiter.until_n_ready(n).await;
                        }
                    }
                }
            }
        }
    }

    fn handle_blob_prefetch_request(
        mgr: Arc<AsyncWorkerMgr>,
        cache: Arc<dyn BlobCache>,
        offset: u64,
        size: u64,
        begin_time: SystemTime,
    ) -> Result<()> {
        trace!(
            "storage: prefetch blob {} offset {} size {}",
            cache.blob_id(),
            offset,
            size
        );
        if size == 0 {
            return Ok(());
        }

        // Record how much prefetch data is requested from storage backend.
        // So the average backend merged request size will be prefetch_data_amount/prefetch_requests_count.
        // We can measure merging possibility by this.
        let metrics = mgr.metrics.clone();
        metrics.prefetch_requests_count.inc();
        metrics.prefetch_data_amount.add(size);

        if let Some(obj) = cache.get_blob_object() {
            if let Err(_e) = obj.fetch_range_compressed(offset, size, true) {
                if mgr.retry_times.load(Ordering::Relaxed) > 0 {
                    mgr.retry_times.fetch_sub(1, Ordering::Relaxed);
                    thread::spawn(move || {
                        thread::sleep(Duration::from_secs(1));
                        let msg =
                            AsyncPrefetchMessage::new_blob_prefetch(cache.clone(), offset, size);
                        let _ = mgr.send_prefetch_message(msg);
                    });
                }
            }
        } else {
            warn!("prefetch blob range is not supported");
        }

        metrics.calculate_prefetch_metrics(begin_time);

        Ok(())
    }

    // TODO: Nydus plans to switch backend storage IO stack to full asynchronous mode.
    // But we can't make `handle_fs_prefetch_request` as async due to the fact that
    // tokio doesn't allow dropping runtime in a non-blocking context. Otherwise, prefetch
    // threads always panic in debug program profile. We can achieve the goal when
    // backend/registry also switches to async IO.
    fn handle_fs_prefetch_request(
        mgr: Arc<AsyncWorkerMgr>,
        cache: Arc<dyn BlobCache>,
        req: BlobIoRange,
        begin_time: SystemTime,
    ) -> Result<()> {
        let blob_offset = req.blob_offset;
        let blob_size = req.blob_size;
        trace!(
            "storage: prefetch fs data from blob {} offset {} size {}",
            cache.blob_id(),
            blob_offset,
            blob_size
        );
        if blob_size == 0 {
            return Ok(());
        }

        // Record how much prefetch data is requested from storage backend.
        // So the average backend merged request size will be prefetch_data_amount/prefetch_requests_count.
        // We can measure merging possibility by this.
        mgr.metrics.prefetch_requests_count.inc();
        mgr.metrics.prefetch_data_amount.add(blob_size);

        if let Some(obj) = cache.get_blob_object() {
            obj.prefetch_chunks(&req)?;
        } else {
            cache.prefetch_range(&req)?;
        }

        mgr.metrics.calculate_prefetch_metrics(begin_time);

        Ok(())
    }

    fn shrink_n(&self, n: u32) {
        self.workers.fetch_sub(n, Ordering::Relaxed);
    }

    fn grow_n(&self, n: u32) {
        self.workers.fetch_add(n, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn test_worker_mgr_new() {
        let tmpdir = TempDir::new().unwrap();
        let metrics = BlobcacheMetrics::new("test1", tmpdir.as_path().to_str().unwrap());
        let config = Arc::new(AsyncPrefetchConfig {
            enable: true,
            threads_count: 2,
            batch_size: 0x100000,
            bandwidth_limit: 0x100000,
        });

        let mgr = Arc::new(AsyncWorkerMgr::new(metrics, config).unwrap());
        AsyncWorkerMgr::start(mgr.clone()).unwrap();
        assert_eq!(mgr.ping_requests.load(Ordering::Acquire), 0);
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        thread::sleep(Duration::from_secs(1));
        assert_eq!(mgr.ping_requests.load(Ordering::Acquire), 5);
        assert_eq!(mgr.workers.load(Ordering::Acquire), 2);
        mgr.stop();
        assert_eq!(mgr.workers.load(Ordering::Acquire), 0);
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_err());
    }

    #[test]
    fn test_send_prefetch_message_disabled() {
        let tmpdir = TempDir::new().unwrap();
        let metrics = BlobcacheMetrics::new("test_disabled", tmpdir.as_path().to_str().unwrap());
        let config = Arc::new(AsyncPrefetchConfig {
            enable: false,
            threads_count: 1,
            batch_size: 0x100000,
            bandwidth_limit: 0,
        });

        let mgr = AsyncWorkerMgr::new(metrics, config).unwrap();
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_err());
        assert_eq!(mgr.prefetch_inflight.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_send_prefetch_message_enabled_increments_inflight() {
        let tmpdir = TempDir::new().unwrap();
        let metrics = BlobcacheMetrics::new("test_enabled", tmpdir.as_path().to_str().unwrap());
        let config = Arc::new(AsyncPrefetchConfig {
            enable: true,
            threads_count: 1,
            batch_size: 0x100000,
            bandwidth_limit: 0,
        });

        let mgr = AsyncWorkerMgr::new(metrics, config).unwrap();
        assert_eq!(mgr.prefetch_inflight.load(Ordering::Acquire), 0);
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        assert_eq!(mgr.prefetch_inflight.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_consume_prefetch_budget() {
        let tmpdir = TempDir::new().unwrap();
        let metrics = BlobcacheMetrics::new("test_budget", tmpdir.as_path().to_str().unwrap());
        let config = Arc::new(AsyncPrefetchConfig {
            enable: true,
            threads_count: 1,
            batch_size: 0x100000,
            bandwidth_limit: 0,
        });

        let mgr = AsyncWorkerMgr::new(metrics, config).unwrap();
        assert_eq!(mgr.prefetch_consumed.load(Ordering::Acquire), 0);

        mgr.consume_prefetch_budget(100);
        assert_eq!(mgr.prefetch_consumed.load(Ordering::Acquire), 0);

        mgr.prefetch_inflight.store(1, Ordering::Release);
        mgr.consume_prefetch_budget(256);
        mgr.consume_prefetch_budget(512);
        assert_eq!(mgr.prefetch_consumed.load(Ordering::Acquire), 768);
    }

    #[test]
    fn test_worker_mgr_rate_limiter() {
        let tmpdir = TempDir::new().unwrap();
        let metrics = BlobcacheMetrics::new("test1", tmpdir.as_path().to_str().unwrap());
        let config = Arc::new(AsyncPrefetchConfig {
            enable: true,
            threads_count: 4,
            batch_size: 0x1000000,
            bandwidth_limit: 0x1000000,
        });

        let mgr = Arc::new(AsyncWorkerMgr::new(metrics, config).unwrap());
        AsyncWorkerMgr::start(mgr.clone()).unwrap();

        assert_eq!(mgr.prefetch_delayed.load(Ordering::Acquire), 0);
        assert_eq!(mgr.prefetch_inflight.load(Ordering::Acquire), 0);

        thread::sleep(Duration::from_secs(1));
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(1))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(1))
            .is_ok());
        thread::sleep(Duration::from_secs(1));
        assert_eq!(mgr.prefetch_delayed.load(Ordering::Acquire), 0);
        assert_eq!(mgr.prefetch_inflight.load(Ordering::Acquire), 0);

        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(0x1000000))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(0x1000000))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(u64::MAX))
            .is_ok());
        assert!(mgr.prefetch_inflight.load(Ordering::Acquire) <= 3);
        assert!(mgr.prefetch_inflight.load(Ordering::Acquire) >= 1);
        // Each oversized request clamps to the 16M bucket capacity and drains the
        // 16M/s budget. The bucket starts full, so one request passes immediately
        // and the remaining two are throttled over ~2s. Check mid-throttle (1s)
        // that work is still in-flight and that requests were delayed.
        thread::sleep(Duration::from_secs(1));
        assert!(mgr.prefetch_inflight.load(Ordering::Acquire) >= 1);
        assert!(mgr.prefetch_delayed.load(Ordering::Acquire) >= 1);

        mgr.stop();
        assert_eq!(mgr.workers.load(Ordering::Acquire), 0);
    }
}
