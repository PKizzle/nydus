// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Tar a path out of a running container's filesystem, for `commit --with-path`.
//!
//! The container's view, bind mounts included, is reachable from the host as
//! `/proc/<pid>/root`. Nothing from the container is executed: the walk runs in
//! this process, and every entry is opened with `openat2(RESOLVE_IN_ROOT)`
//! relative to that root, so symlinks and `..` resolve inside the container
//! exactly as they would for a process in it, and can never reach a host file.
//! The last component of each entry is opened `O_NOFOLLOW`, so a symlink is
//! archived as a symlink.
//!
//! The archive matches what `tar --xattrs --ignore-failed-read` produced from
//! inside the container: entries are named by their in-container path (without
//! the leading `/`, which `nydus-image` resolves identically), directories come
//! before their contents, xattrs travel as PAX records, and an entry that cannot
//! be read is skipped with a warning. Hard links are stored as separate files.

use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use tar::{Builder, EntryType, Header, HeaderMode};
use tracing::warn;

use crate::engine::overlay_diff::{append_xattr_records, collect_file_xattrs};

/// Write a tar of `path`, resolved inside the filesystem rooted at `root`
/// (`/proc/<pid>/root` for a container), to `out`.
pub fn write_path_tar(root: &Path, path: &Path, out: &Path) -> Result<()> {
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        bail!(
            "--with-path {} must be an absolute path without `..`",
            path.display()
        );
    }
    let root_fd: OwnedFd = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(root)
        .with_context(|| format!("open the container root {}", root.display()))?
        .into();
    let rel: PathBuf = path.components().skip(1).collect();

    let file = File::create(out).with_context(|| format!("create mount tar {}", out.display()))?;
    let mut builder = Builder::new(BufWriter::new(file));
    builder.mode(HeaderMode::Complete);
    append_tree(&mut builder, root_fd.as_fd(), &rel, true)?;
    builder
        .into_inner()
        .and_then(|w| w.into_inner().map_err(io::Error::from))
        .with_context(|| format!("finish mount tar {}", out.display()))?;
    Ok(())
}

/// Append `rel` and, for a directory, everything below it. Only the entry the
/// user named (`top`) is fatal when it cannot be read.
fn append_tree<W: io::Write>(
    builder: &mut Builder<W>,
    root: BorrowedFd<'_>,
    rel: &Path,
    top: bool,
) -> Result<()> {
    match append_entry(builder, root, rel) {
        Ok(Some(children)) => {
            for child in children {
                append_tree(builder, root, &rel.join(child), false)?;
            }
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) if !top && is_read_error(&e) => {
            warn!(path = %Path::new("/").join(rel).display(), error = %format!("{e:#}"), "skipping unreadable entry");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Append one entry; a directory returns its children, sorted so an unchanged
/// tree yields an identical layer.
fn append_entry<W: io::Write>(
    builder: &mut Builder<W>,
    root: BorrowedFd<'_>,
    rel: &Path,
) -> Result<Option<Vec<PathBuf>>> {
    let shown = Path::new("/").join(rel);
    let fd = open_in_root(root, rel).with_context(|| format!("open {}", shown.display()))?;
    // Reopening through /proc/self/fd reaches the inode `fd` already pins,
    // without resolving any path again.
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    let fd = File::from(fd);
    let md = fd
        .metadata()
        .with_context(|| format!("stat {}", shown.display()))?;
    let kind = md.file_type();
    let mut header = Header::new_gnu();
    header.set_metadata_in_mode(&md, HeaderMode::Complete);

    if kind.is_socket() {
        warn!(path = %shown.display(), "skipping unix socket: not representable in a tar layer");
        return Ok(None);
    }
    if kind.is_symlink() {
        let target =
            read_link(fd.as_fd()).with_context(|| format!("readlink {}", shown.display()))?;
        header.set_entry_type(EntryType::Symlink);
        // `set_link_name` normalises an absolute target into `//...`; store the
        // bytes as they are, and let `append_link` emit a GNU long link only
        // when they do not fit the header.
        let appended = if header
            .set_link_name_literal(target.as_os_str().as_bytes())
            .is_ok()
        {
            builder.append_data(&mut header, rel, io::empty())
        } else {
            builder.append_link(&mut header, rel, &target)
        };
        appended.with_context(|| format!("append {}", shown.display()))?;
        return Ok(None);
    }
    if !(kind.is_dir() || kind.is_file()) {
        // fifo or device node: the header is the whole entry.
        builder
            .append_data(&mut header, rel, io::empty())
            .with_context(|| format!("append {}", shown.display()))?;
        return Ok(None);
    }

    let opened = File::open(&proc_path).with_context(|| format!("open {}", shown.display()))?;
    let xattrs = collect_file_xattrs(&opened, &shown)?;
    if kind.is_file() {
        // A file that shrinks mid-read is padded, one that grows is cut, so the
        // entry always holds exactly the size its header records.
        let size = md.len();
        let data = opened.take(size).chain(io::repeat(0)).take(size);
        append_xattr_records(builder, &xattrs, rel)?;
        builder
            .append_data(&mut header, rel, data)
            .with_context(|| format!("append {}", shown.display()))?;
        return Ok(None);
    }

    // The root of the container itself has no name to archive it under.
    if !rel.as_os_str().is_empty() {
        append_xattr_records(builder, &xattrs, rel)?;
        builder
            .append_data(&mut header, rel, io::empty())
            .with_context(|| format!("append {}", shown.display()))?;
    }
    let mut children: Vec<PathBuf> = fs::read_dir(&proc_path)
        .with_context(|| format!("read directory {}", shown.display()))?
        .map(|e| e.map(|e| PathBuf::from(e.file_name())))
        .collect::<io::Result<_>>()
        .with_context(|| format!("read directory {}", shown.display()))?;
    children.sort();
    Ok(Some(children))
}

/// `openat2(root, rel, O_PATH | O_NOFOLLOW, RESOLVE_IN_ROOT)`.
fn open_in_root(root: BorrowedFd<'_>, rel: &Path) -> io::Result<OwnedFd> {
    let name = if rel.as_os_str().is_empty() {
        CString::new(".")?
    } else {
        CString::new(rel.as_os_str().as_bytes())?
    };
    // SAFETY: open_how is plain data; all-zero is a valid value of every field.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
    loop {
        // SAFETY: `name` and `how` outlive the call, and the size passed is how's.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                name.as_ptr(),
                &how as *const libc::open_how,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if fd >= 0 {
            // SAFETY: openat2 returned a new descriptor this function now owns.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) });
        }
        let err = io::Error::last_os_error();
        // RESOLVE_IN_ROOT answers EAGAIN when a concurrent rename could have
        // moved the walk; the kernel asks for a plain retry.
        if err.raw_os_error() != Some(libc::EAGAIN) {
            return Err(err);
        }
    }
}

/// Target of the symlink an `O_PATH | O_NOFOLLOW` descriptor refers to.
fn read_link(fd: BorrowedFd<'_>) -> io::Result<PathBuf> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: the buffer is valid for its length; an empty path makes
    // readlinkat act on `fd` itself.
    let n = unsafe {
        libc::readlinkat(
            fd.as_raw_fd(),
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

/// Whether an entry failed because it could not be opened or read, which
/// `--ignore-failed-read` tolerated, rather than because the archive could not
/// be written.
fn is_read_error(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<io::Error>())
        .any(|io| {
            matches!(
                io.raw_os_error(),
                Some(
                    libc::EACCES
                        | libc::EPERM
                        | libc::ENOENT
                        | libc::ELOOP
                        | libc::ENOTDIR
                        | libc::EIO
                )
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(tar: &Path) -> Vec<(String, EntryType, Vec<u8>, Option<String>)> {
        let mut archive = tar::Archive::new(File::open(tar).unwrap());
        archive
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let path = e.path().unwrap().to_string_lossy().into_owned();
                let kind = e.header().entry_type();
                let link = e
                    .link_name()
                    .unwrap()
                    .map(|l| l.to_string_lossy().into_owned());
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                (path, kind, data, link)
            })
            .collect()
    }

    /// A container root with a volume holding a file, a subdirectory and
    /// symlinks that would point at host paths if they were followed.
    fn container_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let vol = root.path().join("vol");
        fs::create_dir_all(vol.join("sub")).unwrap();
        fs::write(vol.join("file.txt"), b"hello").unwrap();
        fs::write(vol.join("sub/inner"), b"inner").unwrap();
        std::os::unix::fs::symlink("/", vol.join("abs")).unwrap();
        std::os::unix::fs::symlink("../../../..", vol.join("up")).unwrap();
        std::os::unix::fs::symlink("/vol", root.path().join("alias")).unwrap();
        std::os::unix::fs::symlink("/etc", root.path().join("hostetc")).unwrap();
        root
    }

    #[test]
    fn archives_a_tree_with_symlinks_kept_as_symlinks() {
        let root = container_root();
        let out = root.path().parent().unwrap().join("with-path-tree.tar");
        write_path_tar(root.path(), Path::new("/vol"), &out).unwrap();
        let got = entries(&out);
        fs::remove_file(&out).unwrap();

        let names: Vec<&str> = got.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(
            names,
            [
                "vol",
                "vol/abs",
                "vol/file.txt",
                "vol/sub",
                "vol/sub/inner",
                "vol/up"
            ]
        );
        assert_eq!(got[0].1, EntryType::Directory);
        assert_eq!(got[1].1, EntryType::Symlink);
        assert_eq!(got[1].3.as_deref(), Some("/"));
        assert_eq!(got[2].2, b"hello");
        assert_eq!(got[5].3.as_deref(), Some("../../../.."));
    }

    #[test]
    fn symlinks_on_the_way_resolve_inside_the_container_root() {
        let root = container_root();
        let out = root.path().parent().unwrap().join("with-path-alias.tar");
        // `/alias` -> `/vol` must land on <root>/vol, not on the host's /vol.
        write_path_tar(root.path(), Path::new("/alias/file.txt"), &out).unwrap();
        let got = entries(&out);
        fs::remove_file(&out).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "alias/file.txt");
        assert_eq!(got[0].2, b"hello");
    }

    #[test]
    fn a_symlink_cannot_reach_a_host_file() {
        let root = container_root();
        let out = root.path().parent().unwrap().join("with-path-host.tar");
        // On the host this is /etc/passwd; inside the root it does not exist.
        let err = write_path_tar(root.path(), Path::new("/hostetc/passwd"), &out).unwrap_err();
        let _ = fs::remove_file(&out);
        assert!(format!("{err:#}").contains("No such file"), "{err:#}");
        let err = write_path_tar(root.path(), Path::new("/vol/up/etc/passwd"), &out).unwrap_err();
        let _ = fs::remove_file(&out);
        assert!(format!("{err:#}").contains("No such file"), "{err:#}");
    }

    #[test]
    fn the_named_path_itself_is_archived_as_a_symlink_when_it_is_one() {
        let root = container_root();
        let out = root.path().parent().unwrap().join("with-path-link.tar");
        write_path_tar(root.path(), Path::new("/alias"), &out).unwrap();
        let got = entries(&out);
        fs::remove_file(&out).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, EntryType::Symlink);
        assert_eq!(got[0].3.as_deref(), Some("/vol"));
    }
}
