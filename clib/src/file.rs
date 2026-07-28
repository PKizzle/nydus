// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Implement file operations for RAFS filesystem in userspace.
//!
//! Provide following file operation functions to access files in a RAFS filesystem:
//! - fopen:
//! - fclose:
//! - fread:
//! - fwrite:
//! - fseek:
//! - ftell

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr::null_mut;

use fuse_backend_rs::api::filesystem::{Context, FileSystem};

use crate::{FileSystemState, Inode, NydusFsHandle, set_errno};

/// Magic number for Nydus file handle.
pub const NYDUS_FILE_HANDLE_MAGIC: u64 = 0xedfc_3919_afc3_5187;
/// Value representing an invalid Nydus file handle.
pub const NYDUS_INVALID_FILE_HANDLE: usize = 0;

/// Handle representing a Nydus file object.
pub type NydusFileHandle = usize;

#[repr(C)]
pub(crate) struct FileState {
    magic: u64,
    ino: Inode,
    pos: u64,
    fs_handle: NydusFsHandle,
}

/// Open the file with `path` in readonly mode.
///
/// The `NydusFileHandle` returned should be freed by calling `nydus_close()`.
///
/// # Safety
/// Caller needs to ensure `fs_handle` and `path` are valid, otherwise it may cause memory access
/// violation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nydus_fopen(
    fs_handle: NydusFsHandle,
    path: *const c_char,
) -> NydusFileHandle {
    unsafe {
        if path.is_null() {
            set_errno(libc::EINVAL);
            return null_mut::<FileState>() as NydusFileHandle;
        }
        let fs = match FileSystemState::try_from_handle(fs_handle) {
            Err(e) => {
                set_errno(e);
                return null_mut::<FileState>() as NydusFileHandle;
            }
            Ok(v) => v,
        };

        let path = match CStr::from_ptr(path).to_str() {
            Ok(p) => p,
            Err(_) => {
                set_errno(libc::EINVAL);
                return null_mut::<FileState>() as NydusFileHandle;
            }
        };

        let ino = match lookup_path(fs, path) {
            Ok(ino) => ino,
            Err(e) => {
                set_errno(e);
                return null_mut::<FileState>() as NydusFileHandle;
            }
        };

        let file = Box::new(FileState {
            magic: NYDUS_FILE_HANDLE_MAGIC,
            ino,
            pos: 0,
            fs_handle,
        });

        Box::into_raw(file) as NydusFileHandle
    }
}

/// Resolve `path` to an inode number by walking it component by component from the root.
///
/// RAFS exposes a FUSE-style `lookup(parent, name)` rather than a path-based open, so a path has
/// to be walked. Empty components are skipped so `/a//b` and `a/b` behave like `/a/b`, and `.`
/// is a no-op; `..` is resolved by `lookup` itself, which knows each directory's parent.
///
/// Each successful `lookup` takes a reference on the inode, so every intermediate component is
/// released again before returning — otherwise every open would leak a reference on each
/// directory along the way. The final inode keeps its reference, which `nydus_fclose` drops.
fn lookup_path(fs: &FileSystemState, path: &str) -> Result<Inode, i32> {
    // POSIX resolves an empty path to ENOENT; without this check it would silently
    // resolve to the root directory below.
    if path.is_empty() {
        return Err(libc::ENOENT);
    }

    let ctx = Context::default();
    let mut ino = fs.root_ino;
    let mut pending_forget: Vec<Inode> = Vec::new();

    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        let name = CString::new(component).map_err(|_| libc::EINVAL)?;
        match fs.rafs.lookup(&ctx, ino, &name) {
            // A missing name is NOT an error at the FUSE layer: `Rafs::lookup` answers it
            // with a *negative entry* (`Ok` with inode 0) so the kernel can cache the
            // absence. Treating that as success would hand out a file handle pinned to
            // inode 0. A negative entry holds no reference, so there is nothing extra to
            // forget — but the references already taken along the path still are.
            Ok(entry) if entry.inode == 0 => {
                if ino != fs.root_ino {
                    pending_forget.push(ino);
                }
                for stale in pending_forget {
                    fs.rafs.forget(&ctx, stale, 1);
                }
                return Err(libc::ENOENT);
            }
            Ok(entry) => {
                if ino != fs.root_ino {
                    pending_forget.push(ino);
                }
                ino = entry.inode;
            }
            Err(e) => {
                // The current `ino` is the last component that DID resolve, and its
                // reference is not yet in `pending_forget` (an inode only moves there
                // once the lookup *under* it succeeds). Forgetting only the list would
                // leak that reference on every failed open of a partially valid path.
                if ino != fs.root_ino {
                    pending_forget.push(ino);
                }
                for stale in pending_forget {
                    fs.rafs.forget(&ctx, stale, 1);
                }
                // The RAFS FUSE boundary answers with a raw `Os` error, so `raw_os_error()`
                // is the real errno. The fallback is `EIO`, not `ENOENT`: an error we cannot
                // decode is a failure, and reporting it as "no such file" would tell the
                // caller the path is absent when it may well exist.
                return Err(e.raw_os_error().unwrap_or(libc::EIO));
            }
        }
    }

    for stale in pending_forget {
        fs.rafs.forget(&ctx, stale, 1);
    }

    // A bare "/" resolves to the root, which `lookup` never took a reference on. Take one so
    // that `nydus_fclose`'s unconditional `forget` stays balanced.
    if ino == fs.root_ino {
        let dot = CString::new(".").map_err(|_| libc::EINVAL)?;
        fs.rafs
            .lookup(&ctx, fs.root_ino, &dot)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    }

    Ok(ino)
}

/// Close the file handle returned by `nydus_fopen()`.
///
/// Passing `NYDUS_INVALID_FILE_HANDLE` is a no-op, so closing whatever `nydus_fopen()` returned
/// without checking it first does not fault -- see `nydus_close_rafs()`.
///
/// # Safety
/// Caller needs to ensure `fs_handle` is valid, otherwise it may cause memory access violation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nydus_fclose(handle: NydusFileHandle) {
    unsafe {
        if handle == NYDUS_INVALID_FILE_HANDLE as NydusFileHandle {
            set_errno(libc::EINVAL);
            return;
        }
        let mut file = Box::from_raw(handle as *mut FileState);
        assert_eq!(file.magic, NYDUS_FILE_HANDLE_MAGIC);

        let ctx = Context::default();
        let fs = FileSystemState::from_handle(file.fs_handle);
        fs.rafs.forget(&ctx, file.ino, 1);

        file.magic -= 0x4fdf_ae34_9d9a_03cd;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::tests::open_file_system;
    use crate::nydus_close_rafs;

    fn fopen(fs: NydusFsHandle, path: &str) -> NydusFileHandle {
        let c = CString::new(path).unwrap();
        unsafe { nydus_fopen(fs, c.as_ptr()) }
    }

    #[test]
    fn fopen_resolves_the_requested_path() {
        let fs = open_file_system();
        let root = unsafe { FileSystemState::from_handle(fs) }.root_ino;

        // A nested regular file from the fixture image. Before `nydus_fopen` walked the
        // path it ignored its argument entirely and every handle pointed at the root
        // inode, so this is the assertion that actually pins the fix.
        let handle = fopen(fs, "/hardlink-test/foo");
        assert_ne!(handle, NYDUS_INVALID_FILE_HANDLE as NydusFileHandle);
        let ino = unsafe { &*(handle as *const FileState) }.ino;
        assert_ne!(ino, root, "handle still points at the root inode");

        // A path in a different subtree must resolve somewhere else.
        let other = fopen(fs, "/normal-file-test");
        assert_ne!(other, NYDUS_INVALID_FILE_HANDLE as NydusFileHandle);
        let other_ino = unsafe { &*(other as *const FileState) }.ino;
        assert_ne!(ino, other_ino);

        // ...whereas the two entries in `hardlink-test` are hardlinks to one inode, which is
        // what that fixture directory exists to exercise. Resolving them to the same inode is
        // correct, not a path-resolution bug.
        let link = fopen(fs, "/hardlink-test/test.sh");
        assert_ne!(link, NYDUS_INVALID_FILE_HANDLE as NydusFileHandle);
        assert_eq!(unsafe { &*(link as *const FileState) }.ino, ino);
        unsafe { nydus_fclose(link) };

        unsafe {
            nydus_fclose(handle);
            nydus_fclose(other);
            nydus_close_rafs(fs);
        }
    }

    #[test]
    fn fopen_accepts_leading_and_duplicate_separators() {
        let fs = open_file_system();
        let a = fopen(fs, "/hardlink-test/foo");
        let b = fopen(fs, "hardlink-test//foo");
        let c = fopen(fs, "/./hardlink-test/foo");
        for h in [a, b, c] {
            assert_ne!(h, NYDUS_INVALID_FILE_HANDLE as NydusFileHandle);
        }
        let ino = |h: NydusFileHandle| unsafe { &*(h as *const FileState) }.ino;
        assert_eq!(ino(a), ino(b));
        assert_eq!(ino(a), ino(c));
        unsafe {
            nydus_fclose(a);
            nydus_fclose(b);
            nydus_fclose(c);
            nydus_close_rafs(fs);
        }
    }

    #[test]
    fn fopen_reports_enoent_for_a_missing_path() {
        let fs = open_file_system();
        let handle = fopen(fs, "/no/such/file");
        assert_eq!(handle, NYDUS_INVALID_FILE_HANDLE as NydusFileHandle);
        // Not just "some error": the C ABI must report ENOENT specifically. This is what
        // pins the errno all the way from the RAFS lookup -- if the chain ever loses it, the
        // `unwrap_or(EIO)` fallback fires and this fails rather than passing silently.
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOENT)
        );

        // A partially valid path exercises the error path's reference cleanup: the
        // prefix resolves (taking references), the tail does not. The leak itself is
        // not observable through the C API, but the walk must still fail cleanly.
        let handle = fopen(fs, "/hardlink-test/does-not-exist");
        assert_eq!(handle, NYDUS_INVALID_FILE_HANDLE as NydusFileHandle);

        // POSIX: an empty path is ENOENT, not the root directory.
        let handle = fopen(fs, "");
        assert_eq!(handle, NYDUS_INVALID_FILE_HANDLE as NydusFileHandle);

        unsafe { nydus_close_rafs(fs) };
    }

    #[test]
    fn closing_an_invalid_file_handle_is_rejected_not_fatal() {
        // Mirrors `nydus_close_rafs`: `nydus_fopen` returns NYDUS_INVALID_FILE_HANDLE on
        // failure, and closing it must not fault.
        unsafe { nydus_fclose(NYDUS_INVALID_FILE_HANDLE as NydusFileHandle) };
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn fopen_on_root_returns_the_root_inode() {
        let fs = open_file_system();
        let root = unsafe { FileSystemState::from_handle(fs) }.root_ino;
        let handle = fopen(fs, "/");
        assert_ne!(handle, NYDUS_INVALID_FILE_HANDLE as NydusFileHandle);
        assert_eq!(unsafe { &*(handle as *const FileState) }.ino, root);
        // `nydus_fclose` forgets unconditionally, so the root open must have taken a
        // reference of its own; if it did not, this drops the superblock's.
        unsafe {
            nydus_fclose(handle);
            nydus_close_rafs(fs);
        }
    }
}
