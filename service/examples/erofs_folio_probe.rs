// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Runs the file-backed EROFS partial-folio self-test (`nydus_service::erofs_folio`) and the
//! page-cache-sharing self-test (`nydus_service::erofs_ishare`) in a directory and prints the
//! results. Needs root. Exit status, from the first: 0 unaffected, 1 affected,
//! 2 inconclusive.
//!
//! With an EROFS image as well, mounts a copy of it file-backed as is and again after
//! `pad_to_page_size`, and prints how many entries of each failed to stat or read.
//!
//!     erofs_folio_probe <dir> [<image>]

#[cfg(target_os = "linux")]
fn main() {
    use nydus_service::erofs_folio::{self, PartialFolioStatus};
    use std::path::Path;

    let args: Vec<String> = std::env::args().collect();
    let dir = Path::new(args.get(1).map(String::as_str).unwrap_or("."));
    let status = erofs_folio::self_test(dir, erofs_folio::SELF_TEST_TIMEOUT);
    println!(
        "erofs-folio-probe: page_size={} status={} {:?}",
        nydus_utils::host_page_size(),
        status.label(),
        status
    );
    let ishare = nydus_service::erofs_ishare::self_test(dir, erofs_folio::SELF_TEST_TIMEOUT);
    println!("erofs-ishare-probe: status={} {ishare:?}", ishare.label());
    if let Some(image) = args.get(2) {
        for padded in [false, true] {
            let copy = dir.join(if padded {
                "padded.erofs"
            } else {
                "unpadded.erofs"
            });
            std::fs::copy(image, &copy).expect("copy image");
            if padded {
                erofs_folio::pad_to_page_size(&copy).expect("pad image");
            }
            let len = std::fs::metadata(&copy).expect("stat image").len();
            println!(
                "image {}: {len} bytes, {}",
                copy.display(),
                walk_image(&copy)
            );
        }
    }
    std::process::exit(match status {
        PartialFolioStatus::Unaffected => 0,
        PartialFolioStatus::Affected(_) => 1,
        PartialFolioStatus::Inconclusive(_) => 2,
    });
}

/// Mounts `image` file-backed next to itself, stats and reads every entry, and unmounts.
#[cfg(target_os = "linux")]
fn walk_image(image: &std::path::Path) -> String {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mnt = image.with_extension("mnt");
    std::fs::create_dir_all(&mnt).expect("create mountpoint");
    let source = CString::new(image.as_os_str().as_bytes()).unwrap();
    let target = CString::new(mnt.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated strings that outlive the call.
    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            c"erofs".as_ptr(),
            libc::MS_RDONLY,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return format!("mount failed: {}", std::io::Error::last_os_error());
    }
    let (mut entries, mut failed) = (0, 0);
    let mut dirs = vec![mnt.clone()];
    while let Some(dir) = dirs.pop() {
        let Ok(list) = std::fs::read_dir(&dir) else {
            failed += 1;
            continue;
        };
        for entry in list {
            entries += 1;
            let Ok(entry) = entry else {
                failed += 1;
                continue;
            };
            let path = entry.path();
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => dirs.push(path),
                Ok(m) if m.is_file() && std::fs::read(&path).is_err() => failed += 1,
                Ok(_) => {}
                Err(_) => failed += 1,
            }
        }
    }
    // SAFETY: as above.
    unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    format!("{entries} entries walked, {failed} failed")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("erofs_folio_probe needs Linux");
    std::process::exit(2);
}
