// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! The file-backed EROFS partial-folio metadata bug: detection and mitigation.
//!
//! Linux 7.3 (from e587a984d332, "erofs: use dedicated meta inodes for file-backed mounts") reads
//! the metadata of a file-backed EROFS mount one page-cache folio at a time. When that folio
//! extends past the end of the backing file the read is short, and `erofs_fileio_ki_complete()`
//! fails it with `EIO` ("failed to read inode meta block"). Inodes in the last, partial page of an
//! image cannot be read, and an image smaller than a page cannot be mounted. Fixed upstream by
//! [`UPSTREAM_FIX`] ("erofs: fix metadata reads at the end of file-backed images").
//!
//! The metadata folio is always one page (the meta mapping does not enable large folios), so the
//! trigger is an image whose length is not a multiple of the host page size: 4 KiB-block images
//! on 16K/64K-page kernels, and 512-byte-block (tarfs) images on any page size. Data reads are not
//! affected: they are clamped to the inode size and never read past the extent they map.
//!
//! The mitigation is [`pad_to_page_size`] (or [`page_aligned_source`] for a file nydus does not
//! own): a sparse tail that ends the image on a page boundary costs no disk blocks and reads back
//! as zeros, exactly what a fixed kernel substitutes for the missing bytes. It is applied on every
//! kernel. [`self_test`] tells whether the running kernel needs it, by mounting a tiny
//! crafted image once unpadded and once padded. A distro may backport the fix, so the kernel
//! version alone does not decide it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The upstream commit that fixes the bug.
pub const UPSTREAM_FIX: &str = "52dceb88082b";

/// Whether the running kernel has the bug, as found by [`self_test`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartialFolioStatus {
    /// An image ending inside a page mounts and reads cleanly.
    Unaffected,
    /// The unpadded probe image failed while the padded one read cleanly.
    Affected(String),
    /// The probe could not decide, e.g. no privilege to mount or no file-backed EROFS support.
    Inconclusive(String),
}

impl PartialFolioStatus {
    /// Short, stable name for metrics and status endpoints.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unaffected => "unaffected",
            Self::Affected(_) => "affected",
            Self::Inconclusive(_) => "inconclusive",
        }
    }
}

/// The host page size in bytes.
pub use nydus_utils::host_page_size;

/// Extends `path` with a sparse hole to a multiple of the host page size. A no-op when it
/// already is one.
pub fn pad_to_page_size(path: &Path) -> io::Result<()> {
    let file = fs::OpenOptions::new().write(true).open(path)?;
    let len = file.metadata()?.len();
    let padded = len.next_multiple_of(host_page_size());
    if padded != len {
        file.set_len(padded)?;
    }
    Ok(())
}

/// The path to mount `image` from: `image` itself when it is a page multiple, otherwise a padded
/// copy beside it (`<name>.page-padded`). The caller's file is never modified.
pub fn page_aligned_source(image: &Path) -> io::Result<PathBuf> {
    if fs::metadata(image)?.len().is_multiple_of(host_page_size()) {
        return Ok(image.to_path_buf());
    }
    let mut name = image.file_name().unwrap_or_default().to_os_string();
    name.push(".page-padded");
    let padded = image.with_file_name(&name);
    name.push(".tmp");
    let tmp = image.with_file_name(name);
    // A fresh file (never through a planted symlink), since nydusd may run as root.
    let _ = fs::remove_file(&tmp);
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let staged = io::copy(&mut fs::File::open(image)?, &mut out)
        .and_then(|_| pad_to_page_size(&tmp))
        .and_then(|()| fs::rename(&tmp, &padded));
    if staged.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    staged.map(|()| padded)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Decides the status from the unpadded and padded probe mounts.
fn classify(unpadded: &io::Result<()>, padded: &io::Result<()>) -> PartialFolioStatus {
    match (unpadded, padded) {
        (Ok(()), _) => PartialFolioStatus::Unaffected,
        (Err(e), Ok(())) => PartialFolioStatus::Affected(format!(
            "an image ending inside a page failed ({e}) while the same image padded to the page \
             size read cleanly"
        )),
        (Err(_), Err(e)) => {
            PartialFolioStatus::Inconclusive(format!("file-backed EROFS probe mount failed: {e}"))
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PROBE_FILES: usize = 8;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PROBE_BLOCK: usize = 512;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PROBE_LEN: usize = 4 * PROBE_BLOCK;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ROOT_NID: u64 = 36;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const FILE_NID0: u64 = 48;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn probe_content(i: usize) -> Vec<u8> {
    format!("nydus erofs probe {i}\n").into_bytes()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// A 2 KiB EROFS image with 512-byte blocks, smaller than any page: a superblock, a root
/// directory and [`PROBE_FILES`] small files, all inline. On a kernel with the bug the
/// superblock read itself is short, so the mount fails.
fn probe_image() -> Vec<u8> {
    fn put(img: &mut [u8], off: usize, bytes: &[u8]) {
        img[off..off + bytes.len()].copy_from_slice(bytes);
    }
    // Compact inode with the FLAT_INLINE data layout: data follows the 32-byte inode.
    fn inode(img: &mut [u8], nid: u64, mode: u16, nlink: u16, data: &[u8], ino: u32) {
        let off = nid as usize * 32;
        put(img, off, &(2u16 << 1).to_le_bytes());
        put(img, off + 4, &mode.to_le_bytes());
        put(img, off + 6, &nlink.to_le_bytes());
        put(img, off + 8, &(data.len() as u32).to_le_bytes());
        put(img, off + 20, &ino.to_le_bytes());
        put(img, off + 32, data);
    }

    let mut img = vec![0u8; PROBE_LEN];
    let sb = 1024;
    put(&mut img, sb, &0xE0F5_E1E2u32.to_le_bytes());
    img[sb + 12] = PROBE_BLOCK.trailing_zeros() as u8;
    put(&mut img, sb + 14, &(ROOT_NID as u16).to_le_bytes());
    put(&mut img, sb + 16, &(1 + PROBE_FILES as u64).to_le_bytes());
    put(
        &mut img,
        sb + 36,
        &((PROBE_LEN / PROBE_BLOCK) as u32).to_le_bytes(),
    );

    // Root directory entries, sorted by name: dirents first, then the names they point at.
    let mut entries = vec![
        (".".to_string(), ROOT_NID, 2u8),
        ("..".to_string(), ROOT_NID, 2),
    ];
    entries.extend((0..PROBE_FILES).map(|i| (format!("f{i}"), FILE_NID0 + 2 * i as u64, 1)));
    let mut dir = Vec::new();
    let mut nameoff = entries.len() * 12;
    for (name, nid, file_type) in &entries {
        dir.extend_from_slice(&nid.to_le_bytes());
        dir.extend_from_slice(&(nameoff as u16).to_le_bytes());
        dir.extend_from_slice(&[*file_type, 0]);
        nameoff += name.len();
    }
    for (name, _, _) in &entries {
        dir.extend_from_slice(name.as_bytes());
    }
    inode(&mut img, ROOT_NID, 0o040755, 2, &dir, 1);
    for i in 0..PROBE_FILES {
        let nid = FILE_NID0 + 2 * i as u64;
        inode(&mut img, nid, 0o100644, 1, &probe_content(i), 2 + i as u32);
    }
    img
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::sync::OnceLock;
    use std::sync::mpsc;
    use std::time::Duration;

    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    /// Upper bound for [`self_test`]: two tiny mounts normally take milliseconds.
    pub const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(10);

    static STATUS: OnceLock<PartialFolioStatus> = OnceLock::new();

    /// Runs [`self_test`] in `dir` the first time it is called; later calls return that result.
    pub fn detect_once(dir: &Path) -> &'static PartialFolioStatus {
        STATUS.get_or_init(|| self_test(dir, SELF_TEST_TIMEOUT))
    }

    /// The cached [`detect_once`] result, if the self-test has run.
    pub fn detected() -> Option<&'static PartialFolioStatus> {
        STATUS.get()
    }

    /// Mounts a crafted image that ends inside a page file-backed, the way nydus mounts its own
    /// images, once as is and once padded to the page size, reads every inode of each, and
    /// classifies the kernel. Needs `CAP_SYS_ADMIN`; without it the result is inconclusive. `dir`
    /// should be on the filesystem nydus mounts its images from. A probe that does not finish
    /// within `timeout` is inconclusive and leaves its scratch directory behind.
    pub fn self_test(dir: &Path, timeout: Duration) -> PartialFolioStatus {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let work = dir.join(format!(".erofs-folio-probe-{}-{nanos}", std::process::id()));
        let (tx, rx) = mpsc::channel();
        let thread_work = work.clone();
        let spawned = std::thread::Builder::new()
            .name("erofs-folio-probe".into())
            .spawn(move || {
                let result = run_trials(&thread_work);
                let _ = fs::remove_dir_all(&thread_work);
                let _ = tx.send(result);
            });
        if let Err(e) = spawned {
            return PartialFolioStatus::Inconclusive(format!("failed to spawn probe thread: {e}"));
        }
        match rx.recv_timeout(timeout) {
            Ok(Ok((unpadded, padded))) => classify(&unpadded, &padded),
            Ok(Err(e)) => PartialFolioStatus::Inconclusive(format!(
                "failed to stage probe image in {}: {e}",
                work.display()
            )),
            Err(_) => {
                PartialFolioStatus::Inconclusive(format!("probe did not finish within {timeout:?}"))
            }
        }
    }

    type Trials = (io::Result<()>, io::Result<()>);

    fn run_trials(work: &Path) -> io::Result<Trials> {
        fs::create_dir_all(work)?;
        let image = probe_image();
        let unpadded = work.join("unpadded.erofs");
        let padded = work.join("padded.erofs");
        fs::write(&unpadded, &image)?;
        fs::write(&padded, &image)?;
        pad_to_page_size(&padded)?;
        Ok((
            trial(&unpadded, &work.join("m0"))?,
            trial(&padded, &work.join("m1"))?,
        ))
    }

    /// The outer result is a staging failure; the inner one is the mount-and-read outcome.
    fn trial(image: &Path, mountpoint: &Path) -> io::Result<io::Result<()>> {
        fs::create_dir_all(mountpoint)?;
        let cstr = |p: &Path| {
            CString::new(p.as_os_str().as_bytes())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
        };
        let (source, target) = (cstr(image)?, cstr(mountpoint)?);
        // SAFETY: every pointer is a valid NUL-terminated string that outlives the call.
        let ret = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                c"erofs".as_ptr(),
                libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Ok(Err(io::Error::last_os_error()));
        }
        let read = read_all(mountpoint);
        // SAFETY: as above.
        if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
            // SAFETY: as above.
            unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
        }
        Ok(read)
    }

    /// Lists the root, stats every entry and reads every file in full, checking the contents.
    fn read_all(root: &Path) -> io::Result<()> {
        let mut seen = 0;
        for entry in fs::read_dir(root)? {
            let path = entry?.path();
            fs::symlink_metadata(&path)?;
            let i: usize = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix('f'))
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| io::Error::other(format!("unexpected entry {}", path.display())))?;
            if fs::read(&path)? != probe_content(i) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} read back wrong contents", path.display()),
                ));
            }
            seen += 1;
        }
        if seen != PROBE_FILES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("listed {seen} of {PROBE_FILES} probe files"),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        let eio = || Err(io::Error::from_raw_os_error(libc::EIO));
        assert_eq!(classify(&Ok(()), &Ok(())), PartialFolioStatus::Unaffected);
        assert_eq!(classify(&Ok(()), &eio()), PartialFolioStatus::Unaffected);
        assert!(matches!(
            classify(&eio(), &Ok(())),
            PartialFolioStatus::Affected(_)
        ));
        // Wrong data from the unpadded image is just as unsafe as EIO.
        let zeros = Err(io::Error::new(io::ErrorKind::InvalidData, "zeros"));
        assert!(matches!(
            classify(&zeros, &Ok(())),
            PartialFolioStatus::Affected(_)
        ));
        // Both failing says nothing about this bug: no privilege, no file-backed EROFS, ...
        let eperm = || Err(io::Error::from_raw_os_error(libc::EPERM));
        let status = classify(&eperm(), &eperm());
        assert!(matches!(status, PartialFolioStatus::Inconclusive(_)));
        assert_eq!(status.label(), "inconclusive");
    }

    #[test]
    fn probe_image_ends_inside_every_page() {
        let img = probe_image();
        assert_eq!(img.len(), PROBE_LEN);
        assert!((img.len() as u64) < 4096, "must end inside even a 4K page");
        assert_eq!(&img[1024..1028], &0xE0F5_E1E2u32.to_le_bytes());
        assert_eq!(1u32 << img[1024 + 12], PROBE_BLOCK as u32);
        // Inline data must not cross a block boundary.
        let root = ROOT_NID as usize * 32;
        let root_size = u32::from_le_bytes(img[root + 8..root + 12].try_into().unwrap()) as usize;
        assert!(root % PROBE_BLOCK + 32 + root_size <= PROBE_BLOCK);
        for i in 0..PROBE_FILES {
            let off = (FILE_NID0 as usize + 2 * i) * 32;
            let len = probe_content(i).len();
            assert!(off % PROBE_BLOCK + 32 + len <= PROBE_BLOCK);
            assert_eq!(&img[off + 32..off + 32 + len], &probe_content(i)[..]);
        }
    }

    #[test]
    fn pad_to_page_size_adds_a_hole_once() {
        use std::os::unix::fs::MetadataExt;

        let dir = std::env::temp_dir().join(format!("erofs-folio-pad-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image");
        let page = host_page_size();
        let body: Vec<u8> = (0..(page * 3 + 4096 - 512)).map(|i| i as u8).collect();
        fs::write(&path, &body).unwrap();
        let blocks = fs::metadata(&path).unwrap().blocks();

        pad_to_page_size(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), page * 4);
        assert!(meta.blocks() <= blocks, "the tail must be a hole");
        let padded = fs::read(&path).unwrap();
        assert_eq!(&padded[..body.len()], &body[..]);
        assert!(padded[body.len()..].iter().all(|&b| b == 0));

        pad_to_page_size(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), padded);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn page_aligned_source_copies_only_unaligned_images() {
        let dir = std::env::temp_dir().join(format!("erofs-folio-src-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let page = host_page_size() as usize;

        let aligned = dir.join("aligned");
        fs::write(&aligned, vec![1u8; page]).unwrap();
        assert_eq!(page_aligned_source(&aligned).unwrap(), aligned);

        let bootstrap = dir.join("bootstrap");
        fs::write(&bootstrap, vec![7u8; page + 512]).unwrap();
        let source = page_aligned_source(&bootstrap).unwrap();
        assert_eq!(source, dir.join("bootstrap.page-padded"));
        assert_eq!(fs::metadata(&bootstrap).unwrap().len(), page as u64 + 512);
        let padded = fs::read(&source).unwrap();
        assert_eq!(padded.len(), 2 * page);
        assert_eq!(&padded[..page + 512], &vec![7u8; page + 512][..]);
        assert!(!dir.join("bootstrap.page-padded.tmp").exists());

        // A changed bootstrap replaces the stale copy.
        fs::write(&bootstrap, vec![9u8; 512]).unwrap();
        assert_eq!(
            fs::read(page_aligned_source(&bootstrap).unwrap()).unwrap()[0],
            9
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
