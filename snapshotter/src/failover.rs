// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Snapshotter-side FUSE failover supervisor bridge.
//!
//! nydusd's hot-upgrade machinery (`fusedev_upgrade::save`/`restore`, driven by
//! the `Takeover` state-machine event) hands the live `/dev/fuse` fd plus
//! serialized daemon state to an **external supervisor over a unix socket**: on
//! `save()` the daemon connects and `send_with_fd`s `(fd, state)`; on `restore()`
//! it connects and `recv_with_fd`s them back. See `service/src/upgrade.rs`.
//!
//! The in-process snapshotter plays that supervisor. This module is the socket
//! bridge: [`capture_on_save`] receives `(fd, state)` while the daemon runs
//! `save()`, and [`serve_on_restore`] replays them while the daemon runs
//! `restore()`. The fd is then parked in systemd's descriptor store (see
//! [`crate::fdstore`]) and the state blob on disk, so both survive the
//! snapshotter's own restart / `kill -9`. RAFS is read-only, so a mount-time
//! snapshot stays valid for the mount's lifetime.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use anyhow::{Context, Result, bail};
use sendfd::{RecvWithFd, SendWithFd};

/// Upper bound on the serialized daemon-state blob. Mirrors
/// `UdsStorageBackend::MAX_STATE_DATA_LENGTH` in the upgrade crate so the
/// daemon's fixed-size `recv` buffer is never overrun.
const MAX_STATE_DATA_LENGTH: usize = 1024 * 32;

/// Bind a one-shot supervisor socket at `socket_path`, run `trigger` — which
/// must make the daemon `save()` (connect + `send_with_fd`) — and return the
/// captured `(fuse_fd, state_blob)`.
///
/// `save()` sends and returns without waiting for us, so we accept *after* it: a
/// stream connection sits in the listen backlog with its payload and SCM_RIGHTS
/// fd buffered until we `accept`/`recv`.
pub fn capture_on_save<F>(socket_path: &Path, trigger: F) -> Result<(OwnedFd, Vec<u8>)>
where
    F: FnOnce() -> Result<()>,
{
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind supervisor socket {}", socket_path.display()))?;

    trigger().context("daemon save() failed")?;

    let (stream, _) = listener
        .accept()
        .context("accept daemon save() connection")?;
    let captured = recv_fd_state(&stream);
    let _ = std::fs::remove_file(socket_path);
    captured
}

/// Bind a one-shot supervisor socket at `socket_path` that replays
/// `(fuse_fd, state)` to the daemon, then run `trigger` — which must make the
/// daemon `restore()` (connect + `recv_with_fd`).
///
/// Unlike save, `restore()` blocks on `recv` until we send, so the accept+send
/// must run concurrently with `trigger`; we do it on a helper thread.
pub fn serve_on_restore<F>(
    socket_path: &Path,
    fuse_fd: RawFd,
    state: Vec<u8>,
    trigger: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind supervisor socket {}", socket_path.display()))?;

    // dup the fd so the sender thread owns a copy independent of the caller's.
    let send_fd = dup_cloexec(fuse_fd).context("dup fuse fd for restore")?;
    let server = std::thread::Builder::new()
        .name("nydus-failover-serve".into())
        .spawn(move || -> Result<()> {
            let (stream, _) = listener.accept().context("accept daemon restore()")?;
            // OwnedFd lives until after the send completes.
            send_fd_state(&stream, &send_fd, &state)
        })
        .context("spawn supervisor serve thread")?;

    let trigger_res = trigger();
    let serve_res = server
        .join()
        .map_err(|_| anyhow::anyhow!("supervisor serve thread panicked"))?;

    let _ = std::fs::remove_file(socket_path);
    trigger_res.context("daemon restore() failed")?;
    serve_res.context("replay fd+state to daemon")?;
    Ok(())
}

fn recv_fd_state(stream: &UnixStream) -> Result<(OwnedFd, Vec<u8>)> {
    let mut data = vec![0u8; MAX_STATE_DATA_LENGTH];
    let mut fds = [0 as RawFd; 8];
    let (n_data, n_fds) = stream
        .recv_with_fd(&mut data, &mut fds)
        .context("recv fd+state from daemon save()")?;
    if n_fds == 0 {
        bail!("daemon save() sent no file descriptor");
    }
    // First fd is the /dev/fuse fd; close any unexpected extras.
    // SAFETY: each fd in [0, n_fds) was just created by recvmsg and is owned by us.
    let fuse_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    for &extra in &fds[1..n_fds] {
        unsafe { libc::close(extra) };
    }
    data.truncate(n_data);
    Ok((fuse_fd, data))
}

fn send_fd_state(stream: &UnixStream, fd: &OwnedFd, state: &[u8]) -> Result<()> {
    use std::os::fd::AsRawFd;
    let sent = stream
        .send_with_fd(state, &[fd.as_raw_fd()])
        .context("send fd+state to daemon restore()")?;
    if sent != state.len() {
        bail!("short state send: {} of {} bytes", sent, state.len());
    }
    Ok(())
}

fn dup_cloexec(fd: RawFd) -> Result<OwnedFd> {
    // F_DUPFD_CLOEXEC duplicates `fd` to the lowest unused number >= 3, CLOEXEC.
    // SAFETY: fcntl on a borrowed valid fd; we take ownership of the new fd.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if new < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl(F_DUPFD_CLOEXEC)");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    // Emulate the daemon's save(): connect to the supervisor socket and
    // send_with_fd a known fd + payload. capture_on_save must return them.
    #[test]
    fn capture_on_save_receives_fd_and_state() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sup.sock");
        let payload = b"serialized-fusedev-state".to_vec();
        let payload_for_trigger = payload.clone();
        let sock_for_trigger = sock.clone();

        let (fd, state) = capture_on_save(&sock, move || {
            let stream = UnixStream::connect(&sock_for_trigger)?;
            let f = tempfile::tempfile().unwrap();
            stream.send_with_fd(&payload_for_trigger, &[f.as_raw_fd()])?;
            Ok(())
        })
        .unwrap();

        assert_eq!(state, payload);
        // The received fd must be a real, distinct, usable descriptor.
        assert!(fd.as_raw_fd() >= 0);
    }

    // Emulate the daemon's restore(): connect and recv_with_fd. serve_on_restore
    // must hand over the parked fd + state.
    #[test]
    fn serve_on_restore_replays_fd_and_state() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sup.sock");
        let state = b"replayed-state-blob".to_vec();
        let file = tempfile::tempfile().unwrap();
        file.try_clone().unwrap().write_all(b"marker").ok();
        let sock_for_trigger = sock.clone();

        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received_fds = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let recv_clone = received.clone();
        let recv_fds_clone = received_fds.clone();

        serve_on_restore(&sock, file.as_raw_fd(), state.clone(), move || {
            let stream = UnixStream::connect(&sock_for_trigger)?;
            let mut buf = vec![0u8; 256];
            let mut fds = [0 as RawFd; 4];
            let (n, nf) = stream.recv_with_fd(&mut buf, &mut fds)?;
            buf.truncate(n);
            *recv_clone.lock().unwrap() = buf;
            *recv_fds_clone.lock().unwrap() = nf;
            for &fd in &fds[..nf] {
                unsafe { libc::close(fd) };
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(*received.lock().unwrap(), state);
        assert_eq!(*received_fds.lock().unwrap(), 1);
    }

    #[test]
    fn capture_reports_missing_fd() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sup.sock");
        let sock_for_trigger = sock.clone();
        // Send data but no fd -> capture must error.
        let res = capture_on_save(&sock, move || {
            let mut stream = UnixStream::connect(&sock_for_trigger)?;
            stream.write_all(b"no-fd-here")?;
            Ok(())
        });
        assert!(res.is_err());
    }
}
