// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Open-file (`RLIMIT_NOFILE`) limit helpers shared by the long-running binaries.

use std::io;

use rlimit::Resource;

/// Minimal number of file descriptors reserved for the rest of the system.
pub const RLIMIT_NOFILE_RESERVED: u64 = 16384;
/// Upper bound for a raised per-process file descriptor limit.
pub const RLIMIT_NOFILE_MAX: u64 = 1_000_000;

/// System-wide open-file limit (`fs.file-max` on Linux, `kern.maxfiles` on macOS).
#[cfg(target_os = "linux")]
pub fn system_file_max() -> io::Result<u64> {
    let file_max = std::fs::read_to_string("/proc/sys/fs/file-max")?;
    file_max.trim().parse::<u64>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid content from fs.file-max {:?}: {e}",
                file_max.trim()
            ),
        )
    })
}

/// System-wide open-file limit (`fs.file-max` on Linux, `kern.maxfiles` on macOS).
#[cfg(target_os = "macos")]
pub fn system_file_max() -> io::Result<u64> {
    let mut mib = [libc::CTL_KERN, libc::KERN_MAXFILES];
    let mut file_max: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: `mib`, `file_max` and `size` are valid for the duration of the call, and
    // `size` matches the buffer `file_max` points to.
    let res = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut file_max) as *mut libc::c_int as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file_max as u64)
}

/// Soft `RLIMIT_NOFILE` to aim for: the hard limit, capped so the rest of the system keeps
/// `RLIMIT_NOFILE_RESERVED` fds and at `RLIMIT_NOFILE_MAX`, but never below the current soft
/// limit. The kernel already keeps the hard limit at or below `fs.nr_open`.
pub fn nofile_soft_target(soft: u64, hard: u64, system_max: u64) -> u64 {
    let cap = hard
        .min(system_max.saturating_sub(RLIMIT_NOFILE_RESERVED))
        .min(RLIMIT_NOFILE_MAX);
    soft.max(cap)
}

/// Raise the soft `RLIMIT_NOFILE` towards the hard limit, as Go programs do at startup.
///
/// Returns the `(old, new)` soft limits. The soft limit is never lowered.
pub fn raise_nofile_soft_limit() -> io::Result<(u64, u64)> {
    let (soft, hard) = Resource::NOFILE.get()?;
    let target = nofile_soft_target(soft, hard, system_file_max()?);
    if target <= soft {
        return Ok((soft, soft));
    }
    // Applies the macOS `kern.maxfilesperproc` cap on top of `target`.
    let new = rlimit::increase_nofile_limit(target)?;
    Ok((soft, new))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nofile_soft_target() {
        // Inherited 1024 under a 524288 hard limit on a roomy system: go to the hard limit.
        assert_eq!(nofile_soft_target(1024, 524_288, 9_000_000), 524_288);
        // Unlimited hard limit: cap at RLIMIT_NOFILE_MAX.
        assert_eq!(
            nofile_soft_target(1024, u64::MAX, u64::MAX),
            RLIMIT_NOFILE_MAX
        );
        // Small system-wide limit: leave the reserve for everyone else.
        assert_eq!(
            nofile_soft_target(1024, 524_288, 100_000),
            100_000 - RLIMIT_NOFILE_RESERVED
        );
        // Never lower an already higher soft limit.
        assert_eq!(nofile_soft_target(800_000, 1_048_576, 100_000), 800_000);
        // System limit below the reserve: keep the current soft limit.
        assert_eq!(nofile_soft_target(1024, 524_288, 1000), 1024);
    }
}
