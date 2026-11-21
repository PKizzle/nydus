// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! fanotify helpers shared by the blob cache and the fanotify pre-content handler.

use std::fs::File;
use std::io::{ErrorKind, Result};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// How long [`open_without_events`] waits for its own opens to arrive as events.
const OPEN_WITHOUT_EVENTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Open the inodes behind `fds` again, read-write or read-only, through `FAN_OPEN_PERM` events
/// of one private fanotify group, returning one descriptor per input, in order. The kernel opens
/// event descriptors with `FMODE_NONOTIFY`, so I/O through them raises no fanotify events even
/// while the inodes carry pre-content marks.
pub fn open_without_events(fds: &[RawFd], writable: bool) -> Result<Vec<OwnedFd>> {
    open_without_events_via(fds, writable, |path| File::open(path))
}

/// [`open_without_events`] with the opener supplied, so a failing open can be tested.
///
/// A failed open raises no event, so the opener reports each result and the group is polled
/// with a deadline: either failure ends the wait with an error instead of blocking forever.
fn open_without_events_via(
    fds: &[RawFd],
    writable: bool,
    open: impl Fn(&str) -> Result<File> + Send + 'static,
) -> Result<Vec<OwnedFd>> {
    if fds.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: `fanotify_init` only takes integer flags; the result is checked below.
    let raw = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
            (if writable {
                libc::O_RDWR
            } else {
                libc::O_RDONLY
            }) as u32,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `raw` is the new group descriptor (checked non-negative above) and nothing else owns
    // it. Dropping the group on any return answers whatever is still queued, so the opener below
    // cannot be left blocked.
    let group = unsafe { OwnedFd::from_raw_fd(raw) };
    for &fd in fds {
        // SAFETY: `raw` is the live group fd owned by `group`, `fd` is a descriptor the caller
        // keeps open for this call, and a NULL path marks `fd` itself.
        if unsafe {
            libc::fanotify_mark(
                raw,
                libc::FAN_MARK_ADD,
                libc::FAN_OPEN_PERM,
                fd,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    let identities = fds
        .iter()
        .map(|&fd| fd_identity(fd))
        .collect::<Result<Vec<_>>>()?;
    let paths: Vec<String> = fds.iter().map(|fd| format!("/proc/self/fd/{fd}")).collect();
    let (opened_tx, opened) = std::sync::mpsc::channel();
    let opener = std::thread::spawn(move || {
        for path in paths {
            let failed = opened_tx.send(open(&path).map(drop)).is_err();
            if failed {
                return;
            }
        }
    });

    let deadline = std::time::Instant::now() + OPEN_WITHOUT_EVENTS_TIMEOUT;
    let mut buf = vec![0u8; 4096];
    let mut found: Vec<Option<OwnedFd>> = fds.iter().map(|_| None).collect();
    let result = loop {
        if found.iter().all(Option::is_some) {
            break Ok(found.into_iter().flatten().collect());
        }
        // An open returns only once its event is answered, so only a failed one is news.
        if let Ok(Err(e)) = opened.try_recv() {
            break Err(e);
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        let mut pfd = libc::pollfd {
            fd: raw,
            events: libc::POLLIN,
            revents: 0,
        };
        // Short slices, so an opener failure is noticed without waiting out the deadline.
        let slice = left.min(std::time::Duration::from_millis(20)).as_millis() as libc::c_int;
        // SAFETY: `pfd` is a live, initialized `pollfd` and the count is 1.
        if unsafe { libc::poll(&mut pfd, 1, slice) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            break Err(e);
        }
        // SAFETY: `buf` is writable for `buf.len()` bytes and `raw` is the live group fd.
        let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                continue;
            }
            break Err(e);
        }
        for_each_parsable_event(&buf[..n as usize], |meta, _| {
            if meta.fd < 0 {
                return;
            }
            // Every opener of the inodes is allowed; only our own opens' descriptors are kept.
            allow(raw, meta.fd);
            // SAFETY: every event with `fd >= 0` carries a fresh descriptor the kernel installed
            // for this process, owned by whoever reads the event; it is wrapped exactly once.
            let event_fd = unsafe { OwnedFd::from_raw_fd(meta.fd) };
            if meta.pid as u32 != std::process::id() {
                return;
            }
            let Ok(identity) = fd_identity(event_fd.as_raw_fd()) else {
                return;
            };
            if let Some(slot) = identities
                .iter()
                .zip(found.iter_mut())
                .find_map(|(id, slot)| (*id == identity && slot.is_none()).then_some(slot))
            {
                *slot = Some(event_fd);
            }
        });
    };
    drop(group);
    let _ = opener.join();
    result
}

/// Get the `(st_dev, st_ino)` identity of an open file descriptor.
///
/// Used to map an event fd back to the file it refers to, without depending on path names.
pub fn fd_identity(fd: RawFd) -> Result<(u64, u64)> {
    // SAFETY: `stat` is plain-old-data; `fstat` only writes into it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a writable `stat` that outlives the call; a bad fd only makes `fstat` fail.
    let ret = unsafe { libc::fstat(fd, &mut st) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((st.st_dev as u64, st.st_ino as u64))
}

/// Walk a raw fanotify event buffer, invoking `f` for every record that can be trusted.
///
/// Stops at the first unparsable record — an unknown metadata version or an `event_len` that
/// is too small or runs past the buffer means the *next* record boundary is guesswork, and a
/// misread `fd` field would have the caller answer on (or close) an arbitrary descriptor.
///
/// Only used off the hot path (shutdown drain, structural-failure recovery); the serving loop
/// of the fanotify handler needs per-record error handling and does its
/// own walk.
pub fn for_each_parsable_event(
    buf: &[u8],
    mut f: impl FnMut(&libc::fanotify_event_metadata, &[u8]),
) {
    let mut offset = 0usize;
    while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= buf.len() {
        // SAFETY: we verified the buffer has enough bytes; the event buffer is a `Vec<u8>` with no
        // alignment guarantee, so the record is copied out rather than referenced.
        let meta = unsafe {
            std::ptr::read_unaligned(
                buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata
            )
        };
        let meta_len = meta.event_len as usize;
        if meta.vers != libc::FANOTIFY_METADATA_VERSION
            || meta_len < std::mem::size_of::<libc::fanotify_event_metadata>()
            || offset + meta_len > buf.len()
        {
            break;
        }
        f(&meta, &buf[offset..offset + meta_len]);
        offset += meta_len;
    }
}

/// Answer `event_fd` with `FAN_ALLOW`, retrying an interrupted write.
fn allow(group: RawFd, event_fd: RawFd) {
    let resp = libc::fanotify_response {
        fd: event_fd,
        response: libc::FAN_ALLOW,
    };
    loop {
        // SAFETY: `resp` is a live `#[repr(C)]` response of exactly the size written.
        let ret = unsafe {
            libc::write(
                group,
                (&resp as *const libc::fanotify_response).cast(),
                std::mem::size_of::<libc::fanotify_response>(),
            )
        };
        if ret >= 0 || std::io::Error::last_os_error().kind() != ErrorKind::Interrupted {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reopen that fails raises no open event; waiting for one would block forever, and with
    /// it a takeover at startup. The opener's own error, errno intact, comes back instead.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN for fanotify_init"]
    fn open_without_events_reports_a_failed_open() {
        let files = [(); 2].map(|_| vmm_sys_util::tempfile::TempFile::new().unwrap());
        let fds = files.each_ref().map(|f| f.as_file().as_raw_fd());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(super::open_without_events_via(&fds, true, |_| {
                Err(std::io::Error::from_raw_os_error(libc::EMFILE))
            }));
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("open_without_events hung on a failed open");
        assert_eq!(
            result.err().and_then(|e| e.raw_os_error()),
            Some(libc::EMFILE)
        );
    }

    /// One group reopens every inode, and each descriptor comes back in its input's place.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN for fanotify_init"]
    fn open_without_events_reopens_each_inode_in_order() {
        let files = [(); 3].map(|_| vmm_sys_util::tempfile::TempFile::new().unwrap());
        let fds = files.each_ref().map(|f| f.as_file().as_raw_fd());
        let reopened = super::open_without_events(&fds, true).unwrap();
        assert_eq!(reopened.len(), fds.len());
        for (fd, quiet) in fds.iter().zip(&reopened) {
            assert_eq!(
                super::fd_identity(quiet.as_raw_fd()).unwrap(),
                super::fd_identity(*fd).unwrap()
            );
        }
    }
}
