// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! SDK C wrappers to access `nydus-rafs` and `nydus-storage` functionalities.
//!
//! # Generate Header File
//! Please use cbindgen to generate `nydus.h` header file from rust source code by:
//! ```
//! cargo install cbindgen
//! cbindgen -l c -v -o include/nydus.h
//! ```
//!
//! # Run C Test
//! ```
//! gcc -o nydus -L ../../target/debug/ -lnydus_clib nydus_rafs.c
//! ```

#[macro_use]
extern crate log;
extern crate core;

pub use file::*;
pub use fs::*;

mod file;
mod fs;

/// Type for RAFS filesystem inode number.
pub type Inode = u64;

/// Helper to set libc::errno
#[cfg(target_os = "linux")]
fn set_errno(errno: i32) {
    unsafe { *libc::__errno_location() = errno };
}

/// Helper to set libc::errno
#[cfg(target_os = "macos")]
fn set_errno(errno: i32) {
    unsafe { *libc::__error() = errno };
}

/// Macro to convert C `char *` into rust `&str`.
///
/// The failure path names the offending argument. Returning the caller's error handle with
/// nothing but `errno` set makes this indistinguishable from every other way an entry point
/// can fail, and the most likely way to land here -- handing over a pointer that is not
/// NUL-terminated, so `CStr::from_ptr` reads past the end of it into whatever follows -- is
/// intermittent and produces no other evidence at all.
#[macro_export]
macro_rules! cstr_to_str {
    ($var: ident, $ret: expr) => {{
        let s = CStr::from_ptr($var);
        match s.to_str() {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "invalid UTF-8 in C string argument `{}`: {} (is it NUL-terminated?)",
                    stringify!($var),
                    e
                );
                set_errno(libc::EINVAL);
                return $ret;
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;

    #[test]
    fn test_set_errno() {
        assert_eq!(Error::raw_os_error(&Error::last_os_error()), Some(0));
        set_errno(libc::EINVAL);
        assert_eq!(
            Error::raw_os_error(&Error::last_os_error()),
            Some(libc::EINVAL)
        );
        set_errno(libc::ENOSYS);
        assert_eq!(
            Error::raw_os_error(&Error::last_os_error()),
            Some(libc::ENOSYS)
        );
        set_errno(0);
        assert_eq!(Error::raw_os_error(&Error::last_os_error()), Some(0));
    }
}
