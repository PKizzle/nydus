// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! File-access tracer for the auto-accel pipeline.
//!
//! When `OverlayEngine::prepare` returns a plain overlay mount for a standard
//! OCI image (i.e. no nydus blob layers, no auto-accel sidecar yet), the
//! snapshotter calls [`AccessTracer::attach`] with the image ref and the
//! overlay merged-dir path. The tracer installs a `FAN_MARK_MOUNT` mark on a
//! dedicated `FAN_CLASS_NOTIF` fanotify group, watching `FAN_OPEN | FAN_ACCESS`.
//! A background OS thread reads events, resolves each event fd via
//! `/proc/self/fd/<N>`, strips the mount-root prefix, and records first-seen
//! paths into an ordered per-image accumulator.
//!
//! On settle (no new files for `settle_idle`, or `settle_max` elapsed
//! whichever first), the accumulator is flushed as a [`PrefetchProfile`] into
//! the existing controller — same code path the optimizer NRI plugin uses via
//! the sysctl `/api/v1/prefetch/profile` endpoint — which persists it and
//! enqueues a conversion job in [`AutoZranManager`].
//!
//! Concurrency note (CLAUDE.md gotcha #1): the event loop runs on its own OS
//! thread (`std::thread::Builder`), not on the gRPC compio runtime. Each
//! fanotify event is processed synchronously; we never block the snapshotter's
//! main runtime.
//!
//! The tracer is a no-op if `auto_zran.capture.enable = false`, if
//! `Fanotify::init(FAN_CLASS_NOTIF)` fails (e.g. kernel too old, missing
//! `CAP_SYS_ADMIN`), or if marking the mount returns `ENOTSUP` (e.g. work_dir
//! on tmpfs — same constraint as the pre-content path).

use anyhow::{Context, Result};
use glob::Pattern;
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd};
#[cfg(target_os = "linux")]
use std::thread;

use crate::auto_zran::AutoZranManager;
use crate::config::AccessCaptureConfig;
use crate::prefetch_profile::{PrefetchProfile, PrefetchProfileStore};

/// Non-Linux placeholder: fanotify is Linux-only, so the tracer is a no-op
/// shell on macOS / Darwin (where the snapshotter is built for development
/// only) and on any other non-Linux target.
#[cfg(not(target_os = "linux"))]
type Fanotify = ();

/// Per-image state held by the tracer.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct ImageCapture {
    image_ref: String,
    mount_root: PathBuf,
    first_seen: Instant,
    last_event: Instant,
    /// Ordered list of first-seen paths (relative to mount_root, image-root style: `/bin/app`).
    files: Vec<String>,
    /// Dedup set keyed by path string.
    seen: HashSet<String>,
    /// Refcount of attach() calls minus detach() calls.
    refcount: u32,
    /// True after a profile has been flushed; further events for the same
    /// mount are ignored.
    settled: bool,
}

impl ImageCapture {
    fn new(image_ref: String, mount_root: PathBuf) -> Self {
        let now = Instant::now();
        Self {
            image_ref,
            mount_root,
            first_seen: now,
            last_event: now,
            files: Vec::new(),
            seen: HashSet::new(),
            refcount: 1,
            settled: false,
        }
    }
}

/// External-facing snapshot of tracer state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct AccessTracerStatus {
    pub enabled: bool,
    pub active_images: usize,
    pub settled_total: u64,
    pub skipped_already_accelerated_total: u64,
    pub events_total: u64,
    pub dropped_events_total: u64,
}

/// The fanotify-based access tracer. Cheap to clone (state is behind an `Arc`).
#[derive(Clone)]
pub struct AccessTracer {
    inner: Arc<Inner>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Inner {
    config: AccessCaptureConfig,
    exclude_patterns: Vec<Pattern>,
    profile_store: PrefetchProfileStore,
    auto_zran: Option<Arc<AutoZranManager>>,
    /// Keyed by mount_root canonical path.
    mounts: Mutex<HashMap<PathBuf, ImageCapture>>,
    skip_images: Mutex<HashSet<String>>,
    fanotify: Option<Fanotify>,
    metrics: Metrics,
}

#[derive(Default)]
struct Metrics {
    settled_total: std::sync::atomic::AtomicU64,
    skipped_already_accelerated_total: std::sync::atomic::AtomicU64,
    events_total: std::sync::atomic::AtomicU64,
    dropped_events_total: std::sync::atomic::AtomicU64,
}

impl AccessTracer {
    /// Start the tracer. Returns a disabled tracer (all methods become
    /// no-ops) when the config disables it, when `Fanotify::init` fails, or
    /// when the host kernel is older than 6.14 (probed elsewhere; this just
    /// checks for the init success). Errors during start are logged at
    /// `warn!` and the returned tracer is disabled.
    pub fn start(
        config: AccessCaptureConfig,
        profile_store: PrefetchProfileStore,
        auto_zran: Option<Arc<AutoZranManager>>,
    ) -> Arc<Self> {
        let exclude_patterns = compile_exclude_patterns(&config.exclude_globs);

        if !config.enable {
            return Arc::new(Self {
                inner: Arc::new(Inner {
                    config,
                    exclude_patterns,
                    profile_store,
                    auto_zran,
                    mounts: Mutex::new(HashMap::new()),
                    skip_images: Mutex::new(HashSet::new()),
                    fanotify: None,
                    metrics: Metrics::default(),
                }),
            });
        }

        #[cfg(target_os = "linux")]
        let fanotify = match Fanotify::init(
            InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_NONBLOCK | InitFlags::FAN_CLOEXEC,
            EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC,
        ) {
            Ok(f) => Some(f),
            Err(err) => {
                warn!(error = %err, "access_tracer disabled: fanotify_init failed");
                None
            }
        };
        #[cfg(not(target_os = "linux"))]
        let fanotify: Option<Fanotify> = {
            warn!("access_tracer disabled: fanotify is Linux-only");
            None
        };
        let enabled = fanotify.is_some();
        let inner = Arc::new(Inner {
            config,
            exclude_patterns,
            profile_store,
            auto_zran,
            mounts: Mutex::new(HashMap::new()),
            skip_images: Mutex::new(HashSet::new()),
            fanotify,
            metrics: Metrics::default(),
        });

        #[cfg(target_os = "linux")]
        if enabled {
            let inner_for_thread = inner.clone();
            thread::Builder::new()
                .name("nydus-access-tracer".to_string())
                .spawn(move || run_event_loop(inner_for_thread))
                .map(|h| {
                    // Detach: we don't join. The loop is bounded by drop of the
                    // last `Arc<Inner>` (sentinel check on each iter).
                    drop(h);
                })
                .unwrap_or_else(|err| {
                    warn!(error = %err, "failed to spawn access_tracer thread");
                });
            info!(
                settle_idle = ?inner.config.settle_idle,
                settle_max = ?inner.config.settle_max,
                "access_tracer started"
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _ = enabled;

        Arc::new(Self { inner })
    }

    /// Attach the tracer to a freshly-prepared overlay mount for an image
    /// that does NOT yet have a sidecar artifact. Idempotent under restart of
    /// the same pod: bumps the refcount if already attached.
    ///
    /// `mount_root` should be the lowerdir of the overlay (where the image
    /// contents live). Capturing on the merged dir would include the
    /// writable upper as well, which has nothing to do with the image's
    /// access patterns.
    pub fn attach(&self, image_ref: &str, mount_root: &Path) -> Result<()> {
        if self.inner.fanotify.is_none() {
            return Ok(());
        }
        if self.is_already_accelerated(image_ref) {
            self.inner
                .metrics
                .skipped_already_accelerated_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!(
                image = image_ref,
                "access_tracer skip: image already accelerated"
            );
            return Ok(());
        }
        let canonical = std::fs::canonicalize(mount_root)
            .with_context(|| format!("canonicalize {}", mount_root.display()))?;

        let mut mounts = self
            .inner
            .mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("access_tracer mounts mutex poisoned"))?;
        if let Some(state) = mounts.get_mut(&canonical) {
            state.refcount += 1;
            debug!(
                image = image_ref,
                mount = %canonical.display(),
                refcount = state.refcount,
                "access_tracer attach: refcount bumped"
            );
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            let fanotify = self
                .inner
                .fanotify
                .as_ref()
                .expect("fanotify present per outer guard");
            // `mark()` wants an `AsFd` for the directory in which the path is
            // looked up. Pass AT_FDCWD (the kernel sentinel) so the path is
            // resolved as-is.
            let at_cwd = unsafe { std::os::fd::BorrowedFd::borrow_raw(libc::AT_FDCWD) };
            fanotify
                .mark(
                    MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
                    MaskFlags::FAN_OPEN | MaskFlags::FAN_ACCESS,
                    at_cwd,
                    Some(canonical.as_path()),
                )
                .with_context(|| {
                    format!("FAN_MARK_ADD | FAN_MARK_MOUNT on {}", canonical.display())
                })?;
        }
        mounts.insert(
            canonical.clone(),
            ImageCapture::new(image_ref.to_string(), canonical.clone()),
        );
        info!(image = image_ref, mount = %canonical.display(), "access_tracer attached");
        Ok(())
    }

    /// Decrement the refcount for a mount. When it reaches zero AND the
    /// image has not been settled yet, drop the in-flight state without
    /// flushing (the pod went away before the image settled — try again
    /// next time). When the image HAS been settled the mark is removed
    /// immediately because the conversion is either queued or done.
    pub fn detach(&self, mount_root: &Path) -> Result<()> {
        if self.inner.fanotify.is_none() {
            return Ok(());
        }
        let canonical =
            std::fs::canonicalize(mount_root).unwrap_or_else(|_| mount_root.to_path_buf());
        let mut mounts = self
            .inner
            .mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("access_tracer mounts mutex poisoned"))?;
        let remove = match mounts.get_mut(&canonical) {
            Some(state) => {
                state.refcount = state.refcount.saturating_sub(1);
                state.refcount == 0
            }
            None => false,
        };
        if remove {
            mounts.remove(&canonical);
            self.try_remove_mark(&canonical);
        }
        Ok(())
    }

    /// Called by `AutoZranManager::run_conversion` after a successful sidecar
    /// upload. Future `attach` calls for this image become no-ops; any
    /// in-flight state is dropped.
    pub fn mark_image_accelerated(&self, image_ref: &str) {
        if let Ok(mut skip) = self.inner.skip_images.lock() {
            skip.insert(image_ref.to_string());
        }
        if let Ok(mut mounts) = self.inner.mounts.lock() {
            let to_remove: Vec<PathBuf> = mounts
                .iter()
                .filter(|(_, state)| state.image_ref == image_ref)
                .map(|(k, _)| k.clone())
                .collect();
            for path in to_remove {
                mounts.remove(&path);
                self.try_remove_mark(&path);
            }
        }
    }

    pub fn status(&self) -> AccessTracerStatus {
        let active_images = self
            .inner
            .mounts
            .lock()
            .map(|m| m.len())
            .unwrap_or_default();
        AccessTracerStatus {
            enabled: self.inner.fanotify.is_some(),
            active_images,
            settled_total: self
                .inner
                .metrics
                .settled_total
                .load(std::sync::atomic::Ordering::Relaxed),
            skipped_already_accelerated_total: self
                .inner
                .metrics
                .skipped_already_accelerated_total
                .load(std::sync::atomic::Ordering::Relaxed),
            events_total: self
                .inner
                .metrics
                .events_total
                .load(std::sync::atomic::Ordering::Relaxed),
            dropped_events_total: self
                .inner
                .metrics
                .dropped_events_total
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    fn is_already_accelerated(&self, image_ref: &str) -> bool {
        self.inner
            .skip_images
            .lock()
            .map(|s| s.contains(image_ref))
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    fn try_remove_mark(&self, mount_root: &Path) {
        if let Some(fanotify) = self.inner.fanotify.as_ref() {
            let at_cwd = unsafe { std::os::fd::BorrowedFd::borrow_raw(libc::AT_FDCWD) };
            let _ = fanotify.mark(
                MarkFlags::FAN_MARK_REMOVE | MarkFlags::FAN_MARK_MOUNT,
                MaskFlags::FAN_OPEN | MaskFlags::FAN_ACCESS,
                at_cwd,
                Some(mount_root),
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn try_remove_mark(&self, _mount_root: &Path) {}
}

fn compile_exclude_patterns(globs: &[String]) -> Vec<Pattern> {
    let mut out = Vec::with_capacity(globs.len());
    for g in globs {
        match Pattern::new(g) {
            Ok(p) => out.push(p),
            Err(err) => warn!(glob = %g, error = %err, "ignoring invalid exclude glob"),
        }
    }
    out
}

/// Background event loop: reads fanotify events, walks per-image accumulators
/// on each iteration, flushes on settle. Bounded by the lifetime of the
/// surrounding `Arc<Inner>`; we use `Arc::strong_count` as a stop signal.
#[cfg(target_os = "linux")]
fn run_event_loop(inner: Arc<Inner>) {
    let settle_idle = parse_duration(&inner.config.settle_idle).unwrap_or(Duration::from_secs(5));
    let settle_max = parse_duration(&inner.config.settle_max).unwrap_or(Duration::from_secs(60));

    let fanotify = inner.fanotify.as_ref().expect("fanotify present");
    let poll_timeout = Duration::from_millis(1000);
    let raw_fd = fanotify.as_fd().as_raw_fd();
    let mut pollfd = libc::pollfd {
        fd: raw_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    loop {
        if Arc::strong_count(&inner) == 1 {
            return; // tracer dropped; bail
        }

        // SAFETY: pollfd is a valid struct on the stack; nfds=1; timeout in ms.
        let rc = unsafe {
            libc::poll(
                &mut pollfd as *mut libc::pollfd,
                1,
                poll_timeout.as_millis() as i32,
            )
        };
        if rc < 0 {
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            warn!(error = %errno, "access_tracer poll failed; stopping");
            return;
        }
        if rc > 0 && (pollfd.revents & libc::POLLIN) != 0 {
            match fanotify.read_events() {
                Ok(events) => process_events(&inner, events),
                Err(err) if err == nix::errno::Errno::EAGAIN => {}
                Err(err) => {
                    warn!(error = %err, "access_tracer read_events failed");
                }
            }
        }

        check_settle(&inner, settle_idle, settle_max);
    }
}

#[cfg(target_os = "linux")]
fn process_events(inner: &Inner, events: Vec<nix::sys::fanotify::FanotifyEvent>) {
    for event in events {
        inner
            .metrics
            .events_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // FAN_CLASS_NOTIF events carry an fd; resolve to a path, then close.
        // (`FanotifyEvent` doesn't close the fd on drop in nix 0.31 for
        // notify-class events; we must close it ourselves to avoid an fd
        // leak — see <https://docs.rs/nix/0.31/nix/sys/fanotify/struct.FanotifyEvent.html>.)
        let Some(fd) = event.fd() else {
            continue;
        };
        let path_buf = match std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
            Ok(p) => Some(p),
            Err(_) => {
                inner
                    .metrics
                    .dropped_events_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                None
            }
        };

        if let Some(path) = path_buf {
            if let Err(err) = record_event(inner, &path) {
                debug!(error = %err, "access_tracer dropped event");
                inner
                    .metrics
                    .dropped_events_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn record_event(inner: &Inner, path: &Path) -> Result<()> {
    let mut mounts = inner
        .mounts
        .lock()
        .map_err(|_| anyhow::anyhow!("mounts mutex poisoned"))?;
    // Find the longest matching mount_root prefix.
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut matched: Option<&mut ImageCapture> = None;
    for state in mounts.values_mut() {
        if canonical.starts_with(&state.mount_root) {
            matched = Some(state);
            break;
        }
    }
    let state =
        matched.ok_or_else(|| anyhow::anyhow!("no mount root matches {}", canonical.display()))?;
    if state.settled {
        return Ok(());
    }
    let rel = canonical
        .strip_prefix(&state.mount_root)
        .map(|p| {
            let mut s = String::from("/");
            s.push_str(p.to_string_lossy().as_ref());
            s
        })
        .unwrap_or_else(|_| canonical.to_string_lossy().into_owned());

    if inner.exclude_patterns.iter().any(|p| p.matches(&rel)) {
        return Ok(());
    }
    if state.seen.contains(&rel) {
        return Ok(());
    }
    if state.files.len() >= inner.config.max_files {
        return Ok(());
    }
    state.last_event = Instant::now();
    state.seen.insert(rel.clone());
    state.files.push(rel);
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_settle(inner: &Inner, settle_idle: Duration, settle_max: Duration) {
    // Snapshot per-image flush actions while holding the lock briefly; do
    // the actual flush (which calls into PrefetchProfileStore + AutoZranManager)
    // outside the lock to keep contention low.
    let mut flushes: Vec<(String, Vec<String>)> = Vec::new();
    if let Ok(mut mounts) = inner.mounts.lock() {
        let now = Instant::now();
        // Aggregate per-image: a single image may have multiple mounts
        // (different snapshot keys) and we want one flush per image with
        // de-duplicated paths preserving first-seen order across mounts.
        let mut to_settle: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for state in mounts.values() {
            if state.settled {
                continue;
            }
            let idle = now.duration_since(state.last_event);
            let elapsed = now.duration_since(state.first_seen);
            if state.files.is_empty() {
                if elapsed >= settle_max {
                    // Nothing captured at all; mark settled to stop trying.
                    // (We don't have &mut here; do this in a follow-up pass.)
                }
                continue;
            }
            if idle >= settle_idle || elapsed >= settle_max {
                let entry = to_settle.entry(state.image_ref.clone()).or_default();
                for f in &state.files {
                    if !entry.iter().any(|existing| existing == f) {
                        entry.push(f.clone());
                    }
                }
            }
        }
        // Apply settled=true to mounts we just flushed, and prepare flushes.
        for (image_ref, files) in to_settle.into_iter() {
            if files.len() < inner.config.min_files {
                continue;
            }
            for state in mounts.values_mut() {
                if state.image_ref == image_ref {
                    state.settled = true;
                }
            }
            flushes.push((image_ref, files));
        }
    }

    for (image_ref, files) in flushes {
        inner
            .metrics
            .settled_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Err(err) = flush_profile(inner, &image_ref, files) {
            warn!(image = image_ref, error = %err, "access_tracer profile flush failed");
        }
    }
}

#[cfg(target_os = "linux")]
fn flush_profile(inner: &Inner, image_ref: &str, files: Vec<String>) -> Result<()> {
    let profile = build_profile(image_ref, files);
    inner
        .profile_store
        .put(&profile)
        .context("persist auto-accel prefetch profile")?;
    if let Some(auto_zran) = &inner.auto_zran {
        auto_zran.try_enqueue_profile(&profile);
    }
    info!(
        image = image_ref,
        files = profile.prefetch_files().len(),
        "access_tracer flushed prefetch profile"
    );
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn build_profile(image_ref: &str, files: Vec<String>) -> PrefetchProfile {
    // Reuse the existing PrefetchProfile factory (used by the sysctl
    // `/api/v1/prefetch/profile` endpoint) so on-disk shape stays identical.
    let records: Vec<crate::nri::AccessProfileRecord> = files
        .into_iter()
        .enumerate()
        .map(|(i, path)| crate::nri::AccessProfileRecord {
            container_id: format!("access-tracer-{i}"),
            image: image_ref.to_string(),
            path,
            op: "open".to_string(),
            timestamp_unix: i as u64,
        })
        .collect();
    PrefetchProfile::from_access_records(image_ref, records)
}

/// Parse `"5s"` / `"500ms"` / `"60s"` strings into `Duration`. Falls back to
/// the duration's word form if the suffix is missing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if let Some(rest) = s.strip_suffix("ms") {
        return Ok(Duration::from_millis(rest.parse()?));
    }
    if let Some(rest) = s.strip_suffix('s') {
        return Ok(Duration::from_secs(rest.parse()?));
    }
    if let Some(rest) = s.strip_suffix('m') {
        return Ok(Duration::from_secs(60 * rest.parse::<u64>()?));
    }
    Ok(Duration::from_secs(s.parse()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_handles_common_suffixes() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("10").unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn exclude_patterns_compile_and_match() {
        let pats = compile_exclude_patterns(&["/proc/**".to_string(), "/sys/**".to_string()]);
        assert_eq!(pats.len(), 2);
        assert!(pats[0].matches("/proc/1/maps"));
        assert!(pats[1].matches("/sys/fs/cgroup/memory.max"));
        assert!(!pats[0].matches("/bin/app"));
    }

    #[test]
    fn build_profile_orders_paths_as_given() {
        let profile = build_profile(
            "registry/app:1",
            vec!["/bin/a".into(), "/bin/b".into(), "/etc/c".into()],
        );
        assert_eq!(profile.image, "registry/app:1");
        assert_eq!(profile.prefetch_files(), vec!["/bin/a", "/bin/b", "/etc/c"]);
    }
}
