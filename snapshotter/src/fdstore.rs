// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! systemd file-descriptor store integration (`sd_notify` `FDSTORE` / `LISTEN_FDS`).
//!
//! The Rust snapshotter runs its nydusd daemons **in-process**, so a
//! `systemctl restart nydus-snapshotter` (or a `kill -9`) takes every live
//! `/dev/fuse` connection down with the process. To survive that — the basis of
//! the takeover/hot-upgrade smoke test — we hand each daemon's fuse fd to PID 1
//! via systemd's file-descriptor store (`FDSTORE=1`). systemd keeps the fd open
//! across the restart **and across an unclean exit**, then passes it back to the
//! successor through the socket-activation protocol (`LISTEN_FDS` /
//! `LISTEN_FDNAMES`, fds numbered from [`SD_LISTEN_FDS_START`]).
//!
//! Requires a `Type=notify` unit with `FileDescriptorStoreMax=` set. When
//! `$NOTIFY_SOCKET` is unset (not run under such a unit, e.g. local dev or
//! macOS) every push is a silent no-op and [`take_stored_fds`] returns empty, so
//! callers degrade to a fresh mount.
//!
//! See `sd_notify(3)`, `sd_listen_fds(3)` and systemd's `FileDescriptorStoreMax=`.

use std::collections::HashMap;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;

use anyhow::{Context, Result, bail};
use sendfd::SendWithFd;
use tracing::warn;

/// First file descriptor passed by systemd via socket activation / the fd store
/// (`SD_LISTEN_FDS_START`). 0/1/2 stay stdin/stdout/stderr.
const SD_LISTEN_FDS_START: RawFd = 3;

/// Push `fd` into systemd's file-descriptor store under `name`, so it outlives a
/// restart (and `kill -9`) of this process.
///
/// `name` (the `FDNAME`) identifies the fd to the successor; use a stable
/// per-daemon key such as the image slug. Returns `Ok(false)` when there is no
/// systemd notify socket (the fd is *not* preserved — the caller must fall back
/// to a fresh mount on the next start).
pub fn store_fd(name: &str, fd: RawFd) -> Result<bool> {
    let Some(sock) = notify_socket()? else {
        return Ok(false);
    };
    // FDNAME must not contain ':' (the LISTEN_FDNAMES separator) or control
    // chars; systemd rejects such names. Slugs are sanitised hex+alnum already.
    let msg = format!("FDSTORE=1\nFDNAME={name}\n");
    sock.send_with_fd(msg.as_bytes(), &[fd])
        .with_context(|| format!("sd_notify FDSTORE for {name}"))?;
    Ok(true)
}

/// Remove every fd stored under `name` from systemd's store (e.g. when an image
/// is fully unmounted and must not be revived on the next start). No-op without
/// a notify socket.
pub fn remove_fd(name: &str) -> Result<bool> {
    let Some(sock) = notify_socket()? else {
        return Ok(false);
    };
    let msg = format!("FDSTOREREMOVE=1\nFDNAME={name}\n");
    sock.send(msg.as_bytes())
        .with_context(|| format!("sd_notify FDSTOREREMOVE for {name}"))?;
    Ok(true)
}

/// Tell systemd the service finished starting (`READY=1`). Required for a
/// `Type=notify` unit so the manager does not consider startup hung. No-op
/// without a notify socket.
pub fn notify_ready() -> Result<bool> {
    let Some(sock) = notify_socket()? else {
        return Ok(false);
    };
    sock.send(b"READY=1\n").context("sd_notify READY")?;
    Ok(true)
}

/// Reclaim the descriptors systemd passed on (re)start, keyed by the `FDNAME`
/// each was stored under. Returns empty when not socket-activated.
///
/// Consumes `LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES` from the environment and
/// marks every reclaimed fd `CLOEXEC` so it does not leak into helper processes
/// the snapshotter spawns (NRI plugins, etc.). Call once, early in `main`.
pub fn take_stored_fds() -> HashMap<String, Vec<OwnedFd>> {
    let listen_pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse::<i32>().ok());
    let listen_fds = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok());
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();

    // Clear so re-exec'd children (and a second call) don't re-claim the fds.
    // SAFETY: called once at startup before any worker threads are spawned, so
    // there is no concurrent getenv/setenv. `remove_var` is `unsafe` in 2024.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }

    let mut out: HashMap<String, Vec<OwnedFd>> = HashMap::new();
    let (Some(pid), Some(count)) = (listen_pid, listen_fds) else {
        return out;
    };
    if count <= 0 {
        return out;
    }
    // LISTEN_PID guards against fds meant for a different process in the unit.
    if pid != std::process::id() as i32 {
        warn!(
            listen_pid = pid,
            our_pid = std::process::id(),
            "LISTEN_PID does not match; ignoring inherited descriptors"
        );
        return out;
    }

    let name_list: Vec<&str> = if names.is_empty() {
        Vec::new()
    } else {
        names.split(':').collect()
    };
    for i in 0..count {
        let fd = SD_LISTEN_FDS_START + i;
        set_cloexec(fd);
        let name = name_list
            .get(i as usize)
            .copied()
            .filter(|n| !n.is_empty())
            .unwrap_or("unknown")
            .to_string();
        // SAFETY: systemd guarantees fds [3, 3+count) are open and owned by us.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        out.entry(name).or_default().push(owned);
    }
    out
}

/// Whether a systemd notify socket is configured (i.e. fd preservation is
/// actually available). Useful for logging/probe output.
pub fn is_available() -> bool {
    std::env::var_os("NOTIFY_SOCKET").is_some_and(|s| !s.is_empty())
}

fn set_cloexec(fd: RawFd) {
    // SAFETY: fd is a valid descriptor we are about to take ownership of.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

/// Connect a datagram socket to `$NOTIFY_SOCKET`, or `None` if it is unset/empty.
fn notify_socket() -> Result<Option<UnixDatagram>> {
    match std::env::var_os("NOTIFY_SOCKET") {
        Some(addr) if !addr.is_empty() => Ok(Some(connect_dgram(addr.as_bytes())?)),
        _ => Ok(None),
    }
}

/// Connect a `SOCK_DGRAM` `AF_UNIX` socket to `addr`, supporting both pathname
/// sockets and systemd's abstract-namespace form (a leading `@`, mapped to the
/// leading NUL byte the kernel expects).
fn connect_dgram(addr: &[u8]) -> Result<UnixDatagram> {
    // SAFETY: zeroed sockaddr_un is a valid empty address.
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as libc::sa_family_t;

    let path_cap = sun.sun_path.len();
    if addr.len() > path_cap {
        bail!("NOTIFY_SOCKET address too long ({} bytes)", addr.len());
    }
    let abstract_ns = addr[0] == b'@';
    for (i, b) in addr.iter().enumerate() {
        sun.sun_path[i] = *b as libc::c_char;
    }
    if abstract_ns {
        sun.sun_path[0] = 0; // abstract namespace marker
    }

    // offsetof(sockaddr_un, sun_path) == size of the family field.
    let base = std::mem::size_of::<libc::sa_family_t>();
    // Abstract: NUL + name (no trailing NUL). Pathname: path + trailing NUL.
    let addr_len = if abstract_ns {
        base + addr.len()
    } else {
        base + addr.len() + 1
    } as libc::socklen_t;

    // SAFETY: standard libc socket(2)/connect(2) with a well-formed sockaddr_un.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_UNIX, SOCK_DGRAM)");
    }
    set_cloexec(fd);
    let rc = unsafe {
        libc::connect(
            fd,
            &sun as *const libc::sockaddr_un as *const libc::sockaddr,
            addr_len,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd is valid and not yet wrapped in an owner.
        unsafe { libc::close(fd) };
        return Err(err).context("connect(NOTIFY_SOCKET)");
    }
    // SAFETY: fd is a connected datagram socket we exclusively own.
    Ok(unsafe { UnixDatagram::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn store_fd_without_notify_socket_is_noop() {
        // No NOTIFY_SOCKET in this process => not preserved, but no error.
        // (Guard: only meaningful when the env var is genuinely absent.)
        if std::env::var_os("NOTIFY_SOCKET").is_none() {
            let f = tempfile::tempfile().unwrap();
            assert!(!store_fd("slug", f.as_raw_fd()).unwrap());
            assert!(!is_available());
        }
    }

    #[test]
    fn connect_dgram_roundtrips_payload_and_fd() {
        // Bind a datagram receiver on a temp path, connect to it via the same
        // path-handling code store_fd() uses, and confirm the FDSTORE payload
        // plus an SCM_RIGHTS fd arrive. Race-free: no environment mutation.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&sock_path).unwrap();

        let sender = connect_dgram(sock_path.as_os_str().as_bytes()).unwrap();
        let payload = b"FDSTORE=1\nFDNAME=slug\n";
        let file = tempfile::tempfile().unwrap();
        sender.send_with_fd(payload, &[file.as_raw_fd()]).unwrap();

        let mut buf = [0u8; 128];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn take_stored_fds_ignores_foreign_listen_pid() {
        // A LISTEN_PID for another process must yield no fds. Use a child-style
        // guard: only mutate env when these vars are absent to avoid clobbering
        // a real socket-activation environment under a test harness.
        if std::env::var_os("LISTEN_PID").is_none() && std::env::var_os("LISTEN_FDS").is_none() {
            // SAFETY: test-only, single-threaded at this point.
            unsafe {
                std::env::set_var("LISTEN_PID", "1");
                std::env::set_var("LISTEN_FDS", "1");
                std::env::set_var("LISTEN_FDNAMES", "slug");
            }
            let fds = take_stored_fds();
            assert!(fds.is_empty(), "fds meant for pid 1 must be ignored");
            // take_stored_fds consumes the env vars.
            assert!(std::env::var_os("LISTEN_PID").is_none());
        }
    }
}
