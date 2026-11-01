// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Tar a path out of a running container, from the host side.
//!
//! `nydusify commit --with-path` captures bind-mounted volumes, which never
//! reach the overlay upperdir. They exist only in the container's mount view,
//! which the host reaches through `/proc/<pid>/root`. Everything is read by
//! this process: running any binary from the container's filesystem as host
//! root would hand the container the host.
//!
//! The container controls every name and symlink under that root, so no path
//! is ever resolved by the host's rules:
//!
//! - the requested path is opened with `openat2(RESOLVE_IN_ROOT |
//!   RESOLVE_NO_MAGICLINKS)` anchored at a descriptor for the root, so `..`
//!   and absolute symlinks resolve inside the container's root, and
//!   `/proc/<pid>/fd`-style links cannot jump out of it;
//! - below it the walk opens one component at a time relative to the parent
//!   directory's descriptor with `O_NOFOLLOW`, so a symlink inside the volume
//!   is archived as a symlink and never followed;
//! - every entry is opened `O_PATH` and classified by `fstat` on that
//!   descriptor. Only a regular file is ever opened for reading; devices and
//!   fifos are never opened. Reading a file, listing a directory and reading
//!   xattrs go through `/proc/self/fd/<n>`, which names the inode already
//!   opened, so a rename racing the walk cannot redirect any of them.
//!
//! Entry names are the requested path without its leading `/`: a layer is
//! rooted at `/`, so the volume lands where it was mounted. A volume is a
//! plain directory, not an overlay upperdir, so nothing in it is a whiteout;
//! a file whose name would read as one in an OCI layer is skipped instead.

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use tar::{Builder, EntryType, Header, HeaderMode};
use tracing::{debug, warn};

use super::overlay_diff::{collect_xattrs, is_oci_whiteout_name};

/// What [`write_volume_tar`] archived and what it had to leave out.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VolumeStats {
    /// Entries written to the tar, hardlinks included.
    pub entries: u64,
    /// Entries left out with a warning: unreadable, vanished mid-walk,
    /// sockets, or named like an OCI whiteout.
    pub skipped: u64,
}

/// Write the tar of `path`, resolved inside `root`, to `out`.
///
/// `root` is the container's root as the host sees it (`/proc/<pid>/root`).
pub fn write_volume_tar(root: &Path, path: &Path, out: &Path) -> Result<VolumeStats> {
    let file = File::create(out).with_context(|| format!("create volume tar {}", out.display()))?;
    let mut writer = BufWriter::new(file);
    let stats = write_volume_tar_to(root, path, &mut writer)?;
    writer
        .flush()
        .with_context(|| format!("finish volume tar {}", out.display()))?;
    Ok(stats)
}

/// [`write_volume_tar`] into any writer.
pub fn write_volume_tar_to<W: Write>(root: &Path, path: &Path, out: W) -> Result<VolumeStats> {
    let Ok(name) = path.strip_prefix("/") else {
        bail!("{} must be an absolute path", path.display());
    };
    if name.as_os_str().is_empty() || !name.components().all(|c| matches!(c, Component::Normal(_)))
    {
        bail!(
            "{} must name a path below / without `.` or `..` components",
            path.display()
        );
    }
    let root_dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(root)
        .with_context(|| format!("open the container root {}", root.display()))?;
    let top = open_beneath(root_dir.as_raw_fd(), name.as_os_str())
        .with_context(|| format!("open {} inside the container", path.display()))?;

    let mut walker = Walker {
        builder: Builder::new(out),
        links: HashMap::new(),
        stats: VolumeStats::default(),
    };
    walker.append(top, name)?;
    walker.builder.finish().context("finish the volume tar")?;
    Ok(walker.stats)
}

struct Walker<W: Write> {
    builder: Builder<W>,
    /// `(dev, ino)` of every multiply-linked entry archived so far, and the
    /// name it was archived under.
    links: HashMap<(u64, u64), PathBuf>,
    stats: VolumeStats,
}

impl<W: Write> Walker<W> {
    /// Archive `entry` (an `O_PATH` descriptor) as `name`, and everything
    /// below it when it is a directory.
    fn append(&mut self, entry: File, name: &Path) -> Result<()> {
        let md = entry
            .metadata()
            .with_context(|| format!("stat {}", name.display()))?;
        let ft = md.file_type();
        let skip_reason = if name
            .file_name()
            .is_some_and(|n| is_oci_whiteout_name(Path::new(n)))
        {
            Some("it is named like an OCI whiteout")
        } else if ft.is_socket() {
            Some("a unix socket has no tar representation")
        } else {
            None
        };
        if let Some(why) = skip_reason {
            self.skip(name, why);
            return Ok(());
        }

        let mut header = Header::new_gnu();
        header.set_metadata_in_mode(&md, HeaderMode::Complete);
        if !ft.is_dir()
            && md.nlink() > 1
            && let Some(first) = self.links.get(&(md.dev(), md.ino()))
        {
            header.set_entry_type(EntryType::Link);
            header.set_size(0);
            self.builder
                .append_link(&mut header, name, first)
                .with_context(|| format!("append hardlink {}", name.display()))?;
            self.stats.entries += 1;
            return Ok(());
        }

        if ft.is_symlink() {
            // Symlink xattrs are not read: the only way to reach them by
            // descriptor dereferences the link.
            let target =
                read_link(&entry).with_context(|| format!("read symlink {}", name.display()))?;
            self.builder
                .append_link(&mut header, name, target)
                .with_context(|| format!("append symlink {}", name.display()))?;
        } else if ft.is_file() {
            // Like `tar --ignore-failed-read`: one unreadable file does not
            // sink the whole volume.
            let file = match OpenOptions::new().read(true).open(fd_path(&entry)) {
                Ok(file) => file,
                Err(e) => {
                    self.skip(name, &format!("cannot be read: {e}"));
                    return Ok(());
                }
            };
            self.append_xattrs(&entry, name)?;
            // The container may grow or shrink the file while it is read:
            // write exactly the size the header promises, zero-padded.
            let size = md.len();
            let data = file.take(size).chain(io::repeat(0)).take(size);
            self.builder
                .append_data(&mut header, name, data)
                .with_context(|| format!("append {}", name.display()))?;
        } else if ft.is_dir() {
            self.append_xattrs(&entry, name)?;
            self.builder
                .append_data(&mut header, name, io::empty())
                .with_context(|| format!("append directory {}", name.display()))?;
            self.stats.entries += 1;
            return self.append_children(&entry, name);
        } else {
            // Character and block devices, fifos.
            if ft.is_char_device() || ft.is_block_device() {
                let rdev = md.rdev();
                header.set_device_major(libc::major(rdev))?;
                header.set_device_minor(libc::minor(rdev))?;
            }
            header.set_size(0);
            self.append_xattrs(&entry, name)?;
            self.builder
                .append_data(&mut header, name, io::empty())
                .with_context(|| format!("append {}", name.display()))?;
        }
        if md.nlink() > 1 {
            self.links.insert((md.dev(), md.ino()), name.to_path_buf());
        }
        self.stats.entries += 1;
        Ok(())
    }

    /// Archive the children of the directory `dir`, sorted, so an unchanged
    /// volume yields the same layer digest.
    fn append_children(&mut self, dir: &File, name: &Path) -> Result<()> {
        let listed: io::Result<Vec<OsString>> = fs::read_dir(fd_path(dir))
            .and_then(|entries| entries.map(|e| e.map(|e| e.file_name())).collect());
        let mut children = match listed {
            Ok(children) => children,
            Err(e) => {
                self.skip(name, &format!("its entries cannot be listed: {e}"));
                return Ok(());
            }
        };
        children.sort();
        for child in children {
            let child_name = name.join(&child);
            match open_beneath(dir.as_raw_fd(), &child) {
                Ok(entry) => self.append(entry, &child_name)?,
                // Removed by the running container since the listing.
                Err(e) => self.skip(&child_name, &format!("cannot be opened: {e}")),
            }
        }
        Ok(())
    }

    /// Emit the entry's xattrs as a PAX header, which applies to the record
    /// written right after it.
    fn append_xattrs(&mut self, entry: &File, name: &Path) -> Result<()> {
        let xattrs = collect_xattrs(&fd_path(entry), true)
            .with_context(|| format!("read xattrs of {}", name.display()))?;
        if xattrs.is_empty() {
            return Ok(());
        }
        debug!(path = %name.display(), count = xattrs.len(), "carrying xattrs into the layer");
        self.builder
            .append_pax_extensions(xattrs.iter().map(|(k, v)| (k.as_str(), v.as_slice())))
            .with_context(|| format!("append xattrs of {}", name.display()))
    }

    fn skip(&mut self, name: &Path, why: &str) {
        warn!(path = %name.display(), "leaving a path out of the volume layer: {why}");
        self.stats.skipped += 1;
    }
}

/// `openat2(dirfd, name, O_PATH | O_NOFOLLOW, RESOLVE_IN_ROOT |
/// RESOLVE_NO_MAGICLINKS)`: resolve `name` with `dirfd` as `/`, never leaving
/// it, and return a descriptor for the entry itself (a symlink is not
/// followed when it is the last component).
fn open_beneath(dirfd: RawFd, name: &OsStr) -> io::Result<File> {
    let name = CString::new(name.as_bytes())?;
    // SAFETY: `open_how` is plain integers; all-zero is its documented default.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: `name` is NUL-terminated and `how` outlives the call, whose
    // size argument matches the struct passed.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            name.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this descriptor, and nothing else owns it.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

/// `/proc/self/fd/<n>`: reaches exactly the inode `file` refers to.
fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// The target of the symlink `link` (an `O_PATH` descriptor).
fn read_link(link: &File) -> io::Result<PathBuf> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: the empty path makes `readlinkat` read `link` itself, and the
    // buffer length passed is the buffer's.
    let n = unsafe {
        libc::readlinkat(
            link.as_raw_fd(),
            c"".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    /// One archived entry: name, type, link target, contents and PAX records.
    #[derive(Debug)]
    struct Entry {
        name: String,
        kind: EntryType,
        link: Option<String>,
        data: Vec<u8>,
        pax: Vec<(String, Vec<u8>)>,
    }

    fn archive(root: &Path, path: &str) -> (VolumeStats, Vec<Entry>) {
        let mut out = Vec::new();
        let stats = write_volume_tar_to(root, Path::new(path), &mut out).unwrap();
        let mut ar = tar::Archive::new(out.as_slice());
        let entries = ar
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let pax = e
                    .pax_extensions()
                    .unwrap()
                    .map(|exts| {
                        exts.map(|x| {
                            let x = x.unwrap();
                            (x.key().unwrap().to_string(), x.value_bytes().to_vec())
                        })
                        .collect()
                    })
                    .unwrap_or_default();
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                Entry {
                    name: e.path().unwrap().to_string_lossy().into_owned(),
                    kind: e.header().entry_type(),
                    link: e
                        .link_name()
                        .unwrap()
                        .map(|l| l.to_string_lossy().into_owned()),
                    data,
                    pax,
                }
            })
            .collect();
        (stats, entries)
    }

    fn find<'a>(entries: &'a [Entry], name: &str) -> &'a Entry {
        entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("{name} not archived: {entries:?}"))
    }

    /// A fake container root: `<root>/etc/passwd` holds "inside", which the
    /// host's `/etc/passwd` never does.
    fn fake_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(root.path().join("etc/passwd"), b"inside").unwrap();
        fs::create_dir_all(root.path().join("vol")).unwrap();
        root
    }

    #[test]
    fn a_symlink_out_of_the_volume_is_archived_not_followed() {
        let root = fake_root();
        symlink("/etc", root.path().join("vol/escape")).unwrap();
        fs::write(root.path().join("vol/data"), b"volume data").unwrap();

        let (stats, entries) = archive(root.path(), "/vol");

        assert_eq!(stats.skipped, 0);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["vol", "vol/data", "vol/escape"]);
        let escape = find(&entries, "vol/escape");
        assert_eq!(escape.kind, EntryType::Symlink);
        assert_eq!(escape.link.as_deref(), Some("/etc"));
        assert_eq!(find(&entries, "vol/data").data, b"volume data");
    }

    #[test]
    fn a_path_through_a_symlink_resolves_inside_the_root() {
        let root = fake_root();
        symlink("/etc", root.path().join("vol/escape")).unwrap();

        let (_, entries) = archive(root.path(), "/vol/escape/passwd");

        // The fake root's file, never the host's /etc/passwd.
        assert_eq!(find(&entries, "vol/escape/passwd").data, b"inside");
    }

    #[test]
    fn an_absolute_symlink_on_the_requested_path_resolves_inside_the_root() {
        let root = fake_root();
        fs::write(root.path().join("vol/file"), b"in the volume").unwrap();
        // `/data -> /vol` inside the container; the host has no `/vol`.
        symlink("/vol", root.path().join("data")).unwrap();
        // `..` hops inside a symlink target stop at the root too.
        symlink("../../../../../etc", root.path().join("vol/up")).unwrap();

        let (_, entries) = archive(root.path(), "/data/file");
        assert_eq!(find(&entries, "data/file").data, b"in the volume");

        let (_, entries) = archive(root.path(), "/vol/up/passwd");
        assert_eq!(find(&entries, "vol/up/passwd").data, b"inside");
    }

    #[test]
    fn magic_links_are_refused() {
        // A container's own /proc is a real procfs, whose `root` and `fd/*`
        // links lead anywhere. With the host's / as the root, the path below
        // resolves only by following such a link, and must not.
        let mut out = Vec::new();
        let err = write_volume_tar_to(
            Path::new("/"),
            Path::new("/proc/self/root/etc/hostname"),
            &mut out,
        )
        .unwrap_err();
        let errno = err
            .root_cause()
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error);
        assert_eq!(errno, Some(libc::ELOOP), "{err:#}");
    }

    #[test]
    fn hardlinks_within_the_volume_are_kept() {
        let root = fake_root();
        fs::write(root.path().join("vol/a"), b"shared").unwrap();
        fs::hard_link(root.path().join("vol/a"), root.path().join("vol/b")).unwrap();

        let (_, entries) = archive(root.path(), "/vol");

        assert_eq!(find(&entries, "vol/a").data, b"shared");
        let b = find(&entries, "vol/b");
        assert_eq!(b.kind, EntryType::Link);
        assert_eq!(b.link.as_deref(), Some("vol/a"));
    }

    #[test]
    fn devices_fifos_and_metadata_are_carried() {
        let root = fake_root();
        let fifo = CString::new(root.path().join("vol/pipe").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o640) }, 0);
        // A device node needs CAP_MKNOD; without it only the fifo is checked.
        let dev = CString::new(root.path().join("vol/null").as_os_str().as_bytes()).unwrap();
        let have_dev =
            unsafe { libc::mknod(dev.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) } == 0;
        let file = root.path().join("vol/script");
        fs::write(&file, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o751)).unwrap();

        let mut out = Vec::new();
        write_volume_tar_to(root.path(), Path::new("/vol"), &mut out).unwrap();
        let mut ar = tar::Archive::new(out.as_slice());
        let md = fs::metadata(&file).unwrap();
        let mut seen = 0;
        for e in ar.entries().unwrap() {
            let e = e.unwrap();
            let h = e.header();
            match e.path().unwrap().to_str().unwrap() {
                "vol/pipe" => {
                    assert_eq!(h.entry_type(), EntryType::Fifo);
                    assert_eq!(h.mode().unwrap() & 0o7777, 0o640);
                    seen += 1;
                }
                "vol/null" => {
                    assert_eq!(h.entry_type(), EntryType::Char);
                    assert_eq!(h.device_major().unwrap(), Some(1));
                    assert_eq!(h.device_minor().unwrap(), Some(3));
                    seen += 1;
                }
                "vol/script" => {
                    assert_eq!(h.mode().unwrap() & 0o7777, 0o751);
                    assert_eq!(h.uid().unwrap(), u64::from(md.uid()));
                    assert_eq!(h.gid().unwrap(), u64::from(md.gid()));
                    assert_eq!(h.mtime().unwrap(), md.mtime() as u64);
                    seen += 1;
                }
                _ => {}
            }
        }
        assert_eq!(seen, 2 + usize::from(have_dev));
    }

    #[test]
    fn xattrs_round_trip() {
        let root = fake_root();
        let file = root.path().join("vol/labelled");
        fs::write(&file, b"x").unwrap();
        if xattr::set(&file, "user.nydus.test", b"value").is_err() {
            eprintln!("skipping: filesystem does not support user xattrs");
            return;
        }

        let (_, entries) = archive(root.path(), "/vol");

        assert!(
            find(&entries, "vol/labelled").pax.contains(&(
                "SCHILY.xattr.user.nydus.test".to_string(),
                b"value".to_vec()
            )),
            "{entries:?}"
        );
    }

    #[test]
    fn whiteout_names_and_sockets_are_skipped() {
        let root = fake_root();
        fs::write(root.path().join("vol/.wh.passwd"), b"").unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(root.path().join("vol/sock")).unwrap();

        let (stats, entries) = archive(root.path(), "/vol");

        assert_eq!(stats.skipped, 2);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["vol"]);
    }

    #[test]
    fn an_unreadable_file_is_skipped_with_a_warning() {
        let root = fake_root();
        fs::write(root.path().join("vol/locked"), b"secret").unwrap();
        fs::write(root.path().join("vol/open"), b"public").unwrap();
        fs::set_permissions(
            root.path().join("vol/locked"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        // Readable path down to the volume for an unprivileged fsuid.
        for dir in [root.path(), &root.path().join("vol")] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Root reads a mode-000 file anyway. The fsuid is per thread, and a
        // non-zero one drops CAP_DAC_OVERRIDE for this thread's file access.
        // SAFETY: plain syscalls; the old fsuid is restored before returning.
        let old = unsafe { libc::setfsuid(65534) };

        let mut out = Vec::new();
        let result = write_volume_tar_to(root.path(), Path::new("/vol"), &mut out);
        unsafe { libc::setfsuid(old as libc::uid_t) };

        let stats = result.unwrap();
        assert_eq!(stats.skipped, 1);
        let mut ar = tar::Archive::new(out.as_slice());
        let names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["vol", "vol/open"]);
    }

    #[test]
    fn requested_paths_must_be_absolute_and_plain() {
        let root = fake_root();
        for bad in ["vol", "/", "/vol/../etc"] {
            let mut out = Vec::new();
            assert!(
                write_volume_tar_to(root.path(), Path::new(bad), &mut out).is_err(),
                "{bad}"
            );
        }
    }

    /// The real setup: a process in its own mount namespace, chrooted, with a
    /// volume bind-mounted at `/data` that only its namespace can see.
    #[test]
    #[ignore = "needs root: builds a mount namespace"]
    fn reads_a_bind_mount_through_proc_pid_root() {
        let host = tempfile::tempdir().unwrap();
        let rootfs = host.path().join("rootfs");
        let volume = host.path().join("volume");
        fs::create_dir_all(rootfs.join("data")).unwrap();
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(rootfs.join("etc/passwd"), b"inside").unwrap();
        fs::create_dir_all(&volume).unwrap();
        fs::write(volume.join("volume-file"), b"from the bind mount").unwrap();
        symlink("/etc", volume.join("escape")).unwrap();

        let c = |p: &Path| CString::new(p.as_os_str().as_bytes()).unwrap();
        let (c_root, c_data, c_volume) = (c(&rootfs), c(&rootfs.join("data")), c(&volume));
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the child only makes async-signal-safe syscalls on memory
        // prepared before the fork, then waits to be killed.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                let ok = libc::unshare(libc::CLONE_NEWNS) == 0
                    && libc::mount(
                        std::ptr::null(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        libc::MS_REC | libc::MS_PRIVATE,
                        std::ptr::null(),
                    ) == 0
                    && libc::mount(
                        c_volume.as_ptr(),
                        c_data.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    ) == 0
                    && libc::chroot(c_root.as_ptr()) == 0;
                libc::write(fds[1], [ok as u8].as_ptr().cast(), 1);
                loop {
                    libc::pause();
                }
            }
        }
        let mut ready = [0u8; 1];
        unsafe { libc::read(fds[0], ready.as_mut_ptr().cast(), 1) };
        let proc_root = PathBuf::from(format!("/proc/{pid}/root"));
        let result = std::panic::catch_unwind(|| {
            assert_eq!(ready[0], 1, "the child could not set up its namespace");
            // The host sees an empty mount point: the bind mount is private.
            assert_eq!(fs::read_dir(rootfs.join("data")).unwrap().count(), 0);

            let (_, entries) = archive(&proc_root, "/data");
            assert_eq!(
                find(&entries, "data/volume-file").data,
                b"from the bind mount"
            );
            assert_eq!(find(&entries, "data/escape").kind, EntryType::Symlink);

            let (_, entries) = archive(&proc_root, "/data/escape/passwd");
            assert_eq!(find(&entries, "data/escape/passwd").data, b"inside");
        });
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        result.unwrap();
    }
}
