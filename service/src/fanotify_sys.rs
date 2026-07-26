// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Raw Linux fanotify constants and structures for pre-content hooks (Linux ≥ 6.14).
//!
//! The `nix` crate's `fanotify` module does not yet expose the `FAN_CLASS_PRE_CONTENT` /
//! `FAN_PRE_ACCESS` API introduced in Linux 6.14. This module provides the missing
//! definitions until upstream `nix` gains support.
//!
//! All constants are taken from `<linux/fanotify.h>` as of the kernel 6.14 merge window.
//! The struct layouts are documented in `fanotify(7)`.

#![allow(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]

use std::mem;

// ---------------------------------------------------------------------------
// fanotify_init(2) flags (supplement nix)
// ---------------------------------------------------------------------------

/// Pre-content event class — daemon gets a chance to fill file content before
/// the requesting application sees it.
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;

/// Request file-handle-based reporting. Required to receive `fanotify_event_info_fid`
/// records alongside each event so the daemon can open the target file by handle.
pub const FAN_REPORT_FID: u32 = 0x0000_0200;

/// Report the target file descriptor (pidfd) of the process that triggered the event.
pub const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;

// ---------------------------------------------------------------------------
// fanotify_mark(2) event masks (supplement nix)
// ---------------------------------------------------------------------------

/// An application is about to access file content that is not yet present.
/// The daemon must populate the requested range and respond with `FAN_ALLOW`
/// (or `FAN_DENY` / `FAN_DENY_ERRNO(e)` on failure).
pub const FAN_PRE_ACCESS: u64 = 0x0010_0000;

/// The kernel's event queue overflowed and events were **dropped**.
///
/// Delivered as a synthetic record with `fd == FAN_NOFD` and no information
/// records. For a permission class such as `FAN_CLASS_PRE_CONTENT` the dropped
/// events were fail-opened by the kernel, so this is a data-integrity signal,
/// not a throughput hint — see `FanotifyHandler::process_event_buffer`.
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

/// `fanotify_event_metadata.fd` value meaning "no descriptor for this event".
///
/// Carried by the `FAN_Q_OVERFLOW` record, and by every event when a group is
/// created with `FAN_REPORT_FID` (which this path deliberately does not set).
pub const FAN_NOFD: i32 = -1;

// ---------------------------------------------------------------------------
// fanotify response helpers
// ---------------------------------------------------------------------------

/// Construct a deny-with-errno response (`FAN_DENY_ERRNO(e)` macro from the kernel).
///
/// Kernel ≥ 6.14 supports denying with an errno other than `EPERM` (the `FAN_DENY_ERRNO`
/// response encoding merged with the pre-content series in 6.14; 6.13 added the separate
/// `FAN_REPORT_FD_ERROR` init flag). The kernel macro is
/// `FAN_DENY | ((err & FAN_ERRNO_MASK) << FAN_ERRNO_SHIFT)` with `FAN_ERRNO_BITS = 8`, i.e.
/// the errno occupies the top 8 bits (`FAN_ERRNO_SHIFT = 32 - 8 = 24`).
/// Common choices: `libc::EIO`, `libc::EBUSY`, `libc::ENOSPC`.
#[inline]
pub const fn fan_deny_errno(errno: libc::c_int) -> u32 {
    const FAN_DENY: u32 = 0x0000_0002;
    const FAN_ERRNO_MASK: u32 = 0xFF;
    const FAN_ERRNO_SHIFT: u32 = 24;
    FAN_DENY | (((errno as u32) & FAN_ERRNO_MASK) << FAN_ERRNO_SHIFT)
}

// ---------------------------------------------------------------------------
// fanotify_event_info_type (supplement nix)
// ---------------------------------------------------------------------------

/// `fanotify_event_info_header.info_type` value for a `fanotify_event_info_range`
/// record that trails a `FAN_PRE_ACCESS` event.
pub const FAN_EVENT_INFO_TYPE_RANGE: u8 = 6u8;

// ---------------------------------------------------------------------------
// C-struct layouts (byte-for-byte with kernel ABI)
// ---------------------------------------------------------------------------

/// Generic header prepended to every additional information record in a
/// fanotify event buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fanotify_event_info_header {
    /// Type of the information record (`FAN_EVENT_INFO_TYPE_*`).
    pub info_type: u8,
    pub pad: u8,
    /// Total length of this record, including the header.
    pub len: u16,
}

/// File-handle information record.
///
/// Present when the notification group was created with `FAN_REPORT_FID`.
/// The `handle` bytes give the kernel an opaque identifier that can be
/// passed to `open_by_handle_at(2)` to obtain a file descriptor for the
/// target object.
#[repr(C)]
pub struct fanotify_event_info_fid {
    pub hdr: fanotify_event_info_header,
    /// The filesystem id (`statfs(2).f_fsid`).
    pub fsid: [libc::c_uint; 2],
    /// Variable-length file handle follows here.
    pub handle: [u8; 0],
}

/// Access-range information record for `FAN_PRE_ACCESS` events.
///
/// The daemon must fill `offset .. offset+count` bytes in the target file
/// before responding with `FAN_ALLOW`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fanotify_event_info_range {
    pub hdr: fanotify_event_info_header,
    pub pad: u32,
    /// Starting byte offset of the access.
    pub offset: u64,
    /// Number of bytes requested.
    pub count: u64,
}

// ---- safety assertions ---------------------------------------------------

const _: () = assert!(mem::size_of::<fanotify_event_info_header>() == 4);
const _: () = assert!(mem::size_of::<fanotify_event_info_range>() == 24);

#[cfg(test)]
mod tests {
    use super::*;

    // Golden values from <linux/fanotify.h> (kernel 6.14). The pre-content path
    // fails silently or at mount if any of these drift from the kernel UAPI;
    // this guards against accidental edits. When bumping the minimum kernel,
    // re-verify against /usr/include/linux/fanotify.h.
    #[test]
    fn test_abi_constants_match_kernel_uapi() {
        assert_eq!(FAN_CLASS_PRE_CONTENT, 0x0000_0008);
        assert_eq!(FAN_REPORT_FID, 0x0000_0200);
        assert_eq!(FAN_REPORT_TARGET_FID, 0x0000_1000);
        assert_eq!(FAN_PRE_ACCESS, 0x0010_0000);
        assert_eq!(FAN_Q_OVERFLOW, 0x0000_4000);
        assert_eq!(FAN_NOFD, -1);
        assert_eq!(FAN_EVENT_INFO_TYPE_RANGE, 6u8);
    }

    // FAN_DENY_ERRNO(e) = FAN_DENY(0x02) | ((e & 0xFF) << 24).
    #[test]
    fn test_fan_deny_errno_masks_to_eight_bits() {
        assert_eq!(fan_deny_errno(libc::EIO), 0x0500_0002); // EIO == 5
        assert_eq!(fan_deny_errno(libc::ENOSPC) >> 24, 28); // ENOSPC == 28
        assert_eq!(fan_deny_errno(libc::EDQUOT) >> 24, 122); // EDQUOT == 122
        // Only the low 8 bits of the errno survive; FAN_DENY stays set.
        let encoded = fan_deny_errno(0x1FF);
        assert_eq!(encoded & 0x0000_00FF, 0x02, "FAN_DENY bit preserved");
        assert_eq!(encoded >> 24, 0xFF, "errno masked to 8 bits");
    }

    // The kernel writes `offset`/`count` at fixed positions in the range record;
    // a field reorder or padding change here silently corrupts range parsing.
    #[test]
    fn test_event_info_range_field_offsets() {
        assert_eq!(mem::offset_of!(fanotify_event_info_header, info_type), 0);
        assert_eq!(mem::offset_of!(fanotify_event_info_header, len), 2);

        assert_eq!(mem::offset_of!(fanotify_event_info_range, hdr), 0);
        assert_eq!(mem::offset_of!(fanotify_event_info_range, offset), 8);
        assert_eq!(mem::offset_of!(fanotify_event_info_range, count), 16);
    }
}
