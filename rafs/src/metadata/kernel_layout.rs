// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! What the EROFS kernel driver reads for a RAFS v6 file, checked against what nydus fills.
//!
//! A kernel mount reads a chunk-based file through the inode's chunk indexes: chunk `j` of
//! `1 << chunkbits` bytes is read from `startblk * block_size` of the device its masked
//! `device_id` names. The fill path writes, and validates against its digest, each chunk-table
//! chunk at its uncompressed offset in its blob's cache file. The two views are built from the
//! same bootstrap but by different code, so [`check_kernel_layout`] proves, per regular file,
//! that every byte the kernel can read lies in exactly the chunk the fill path validates for that
//! byte of the file. The 48-bit chunk layout, which would reinterpret the ci index bits as block
//! address bits, cannot occur: loading the superblock rejects every incompatible feature but
//! chunked files and the device table.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nydus_storage::device::{BlobChunkInfo, BlobFeatures, ChunkDigestEntry};

use super::direct_v6::OndiskInodeWrapper;
use super::layout::v5::RafsV5ChunkInfo;
use super::layout::v6::{
    EROFS_CHUNK_FORMAT_INDEXES_FLAG, EROFS_CHUNK_FORMAT_SIZE_MASK, EROFS_INODE_CHUNK_BASED,
    EROFS_SUPER_OFFSET, RafsV6Device, RafsV6SuperBlock, ishare_fingerprint,
    ishare_xattr_prefix_table,
};
use super::{RafsInode, RafsInodeExt, RafsSuper};
use crate::{RafsError, RafsResult};

/// The block address EROFS reads as a hole: zeros, with no device read at all.
const EROFS_NULL_ADDR: u32 = u32::MAX;

/// A way the kernel's reading of a file departs from the chunks the fill path validates.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LayoutViolation {
    #[error("data layout {0} is not chunk-based")]
    NotChunkBased(u16),
    #[error("chunk format 0x{0:x} has no 8-byte indexes or chunks smaller than the RAFS chunk")]
    ChunkFormat(u16),
    #[error("chunk {chunk}: the chunk table has no entry for its address")]
    UnknownChunk { chunk: u32 },
    #[error("chunk {chunk}: blob {blob} is external, not an EROFS device")]
    ExternalBlob { chunk: u32, blob: u32 },
    #[error("chunk {chunk}: the kernel reads device {device}, the chunk is in blob {blob}")]
    DeviceId { chunk: u32, device: u16, blob: u32 },
    #[error("chunk {chunk}: the kernel reads a hole where the chunk table has data")]
    Hole { chunk: u32 },
    #[error(
        "chunk {chunk}: the kernel reads device offset 0x{kernel:x}, the chunk starts at 0x{uncompressed:x}"
    )]
    BlockAddr {
        chunk: u32,
        kernel: u64,
        uncompressed: u64,
    },
    #[error("chunk {chunk}: the kernel reads 0x{expected:x} bytes, the chunk holds 0x{size:x}")]
    ChunkSize {
        chunk: u32,
        size: u32,
        expected: u64,
    },
    #[error("chunk {chunk}: ends at block 0x{end:x}, past the {blocks} blocks of its device")]
    PastDevice { chunk: u32, end: u64, blocks: u64 },
    #[error("chunk {chunk}: device table has no slot {blob}")]
    MissingDevice { chunk: u32, blob: u32 },
    #[error("chunk {chunk}: overlaps another chunk of blob {blob}")]
    Overlap { chunk: u32, blob: u32 },
}

/// The verdict for one path of a regular file.
#[derive(Clone, Debug)]
pub struct FileLayout {
    pub ino: u64,
    pub path: PathBuf,
    /// Empty when the kernel provably reads only validated chunk data for this file.
    pub violations: Vec<LayoutViolation>,
}

/// The verdict for a whole image.
#[derive(Clone, Debug, Default)]
pub struct KernelLayoutReport {
    /// Defects of the image as a whole, which make no file's layout trustworthy.
    pub image_errors: Vec<String>,
    /// Every path of a regular file, hardlinks included.
    pub files: Vec<FileLayout>,
}

impl KernelLayoutReport {
    /// Whether every byte any regular file exposes through a kernel mount is validated data.
    pub fn is_strict(&self) -> bool {
        self.image_errors.is_empty() && self.files.iter().all(|f| f.violations.is_empty())
    }
}

/// Every entry of the bootstrap's chunk table.
fn chunk_table(rs: &RafsSuper) -> RafsResult<Vec<Arc<dyn BlobChunkInfo>>> {
    let unit = size_of::<RafsV5ChunkInfo>();
    let size = rs.meta.chunk_table_size as usize;
    if !size.is_multiple_of(unit) {
        return Err(RafsError::InvalidMetadata(format!(
            "chunk table size {size} is not a multiple of {unit}"
        )));
    }
    (0..size / unit)
        .map(|idx| rs.superblock.get_chunk_info(idx))
        .collect()
}

/// The digest and extent of every chunk the bootstrap references, per blob in blob table order
/// and by chunk index, for validating fills of that blob against the bootstrap.
///
/// Fails when the chunk table records one chunk of a blob twice with different digests or
/// extents, or names a blob or chunk index the blob table lacks.
pub fn chunk_digest_tables(rs: &RafsSuper) -> RafsResult<Vec<Vec<Option<ChunkDigestEntry>>>> {
    if !rs.meta.is_v6() {
        return Err(RafsError::Unsupported);
    }
    let blobs = rs.superblock.get_blob_infos();
    let mut tables: Vec<Vec<Option<ChunkDigestEntry>>> = blobs
        .iter()
        .map(|b| vec![None; b.chunk_count() as usize])
        .collect();
    for chunk in chunk_table(rs)? {
        let (blob, index) = (chunk.blob_index(), chunk.id());
        let slot = tables
            .get_mut(blob as usize)
            .and_then(|t| t.get_mut(index as usize))
            .ok_or_else(|| {
                RafsError::InvalidMetadata(format!(
                    "chunk table names chunk {index} of blob {blob}, which the blob table lacks"
                ))
            })?;
        let entry = ChunkDigestEntry {
            digest: *chunk.chunk_id(),
            uncompressed_offset: chunk.uncompressed_offset(),
            uncompressed_size: chunk.uncompressed_size(),
        };
        match slot {
            Some(known) if *known != entry => {
                return Err(RafsError::InvalidMetadata(format!(
                    "chunk table records chunk {index} of blob {blob} twice, differently"
                )));
            }
            _ => *slot = Some(entry),
        }
    }
    Ok(tables)
}

/// Check, for every regular file of the RAFS v6 image `rs` loaded from `bootstrap`, that the
/// kernel reads exactly the chunk-table chunks the fill path validates.
pub fn check_kernel_layout(rs: &RafsSuper, bootstrap: &Path) -> RafsResult<KernelLayoutReport> {
    if !rs.meta.is_v6() {
        return Err(RafsError::Unsupported);
    }
    let mut report = KernelLayoutReport::default();
    let blobs = rs.superblock.get_blob_infos();
    let chunk_size = rs.meta.chunk_size as u64;

    let file = File::open(bootstrap)?;
    let mut devslots = vec![RafsV6Device::new(); rs.meta.blob_device_table_count as usize];
    for (i, slot) in devslots.iter_mut().enumerate() {
        let offset = rs.meta.blob_device_table_offset + (i * size_of::<RafsV6Device>()) as u64;
        file.read_exact_at(slot.as_mut(), offset)?;
    }
    if devslots.len() != blobs.len() {
        report.image_errors.push(format!(
            "device table has {} slots for {} blobs",
            devslots.len(),
            blobs.len()
        ));
    }
    for (i, (slot, blob)) in devslots.iter().zip(&blobs).enumerate() {
        if slot.blob_id() != blob.blob_id().as_bytes() {
            report.image_errors.push(format!(
                "device {} is {}, blob {i} is {}",
                i + 1,
                String::from_utf8_lossy(slot.blob_id()),
                blob.blob_id()
            ));
        }
    }
    // The kernel keeps only these bits of a chunk's device id, which drops the ci index bits
    // RAFS packs above the blob index.
    let device_id_mask = ((devslots.len() + 1).next_power_of_two() - 1) as u16;

    let mut extents: HashMap<u32, Vec<(u64, u64, u32)>> = HashMap::new();
    for chunk in chunk_table(rs)? {
        let start = chunk.uncompressed_offset();
        extents.entry(chunk.blob_index()).or_default().push((
            start,
            start + chunk.uncompressed_size() as u64,
            chunk.id(),
        ));
    }
    let mut overlapping: HashSet<(u32, u32)> = HashSet::new();
    for (blob, chunks) in &mut extents {
        // The chunk table lists a chunk once per reference; only distinct entries can overlap.
        chunks.sort_unstable();
        chunks.dedup();
        // Two chunks that start at the same offset collide even if one of them is empty: the
        // fill path resolves an offset to one chunk only, and validates that one's digest.
        let mut prev: Option<(u64, u64, u32)> = None;
        for &(start, end, ci) in chunks.iter() {
            if let Some((prev_start, prev_end, prev_ci)) = prev
                && (start < prev_end || start == prev_start)
            {
                overlapping.insert((*blob, prev_ci));
                overlapping.insert((*blob, ci));
            }
            if prev.is_none_or(|(_, prev_end, _)| end >= prev_end) {
                prev = Some((start, end, ci));
            }
        }
    }

    let root = rs.get_extended_inode(rs.superblock.root_ino(), false)?;
    let mut pending = vec![(PathBuf::from("/"), root)];
    while let Some((path, inode)) = pending.pop() {
        if inode.is_dir() {
            for idx in 0..inode.get_child_count() {
                let child = inode.get_child_by_index(idx)?;
                pending.push((path.join(child.name()), child));
            }
            continue;
        }
        if !inode.is_reg() {
            continue;
        }
        let Some(ondisk) = inode.as_any().downcast_ref::<OndiskInodeWrapper>() else {
            continue;
        };
        let mut violations = Vec::new();
        let size = inode.size();
        let (layout, union) = ondisk.data_layout();
        let format = union as u16;
        let kernel_bits = rs.meta.blkszbits as u32 + (format & EROFS_CHUNK_FORMAT_SIZE_MASK) as u32;
        if size == 0 {
            // Nothing to read, whatever the layout.
        } else if layout != EROFS_INODE_CHUNK_BASED {
            violations.push(LayoutViolation::NotChunkBased(layout));
        } else if format & EROFS_CHUNK_FORMAT_INDEXES_FLAG == 0
            || kernel_bits >= 64
            || (1u64 << kernel_bits) < chunk_size
        {
            violations.push(LayoutViolation::ChunkFormat(format));
        } else {
            for idx in 0..inode.get_chunk_count() {
                if let Err(v) = check_chunk(
                    rs,
                    ondisk,
                    idx,
                    kernel_bits,
                    &devslots,
                    device_id_mask,
                    &overlapping,
                ) {
                    violations.push(v);
                }
            }
        }
        report.files.push(FileLayout {
            ino: inode.ino(),
            path,
            violations,
        });
    }
    Ok(report)
}

/// The files of `report` whose inode passes the check on every one of its paths: hardlinks
/// share an inode, so one violating path rules out all of them.
fn fit_files(report: &KernelLayoutReport) -> impl Iterator<Item = &FileLayout> {
    let unfit: HashSet<u64> = report
        .files
        .iter()
        .filter(|f| !f.violations.is_empty())
        .map(|f| f.ino)
        .collect();
    report.files.iter().filter(move |f| !unfit.contains(&f.ino))
}

/// The inode at `path` (absolute, from the root) of `rs`.
fn inode_at(rs: &RafsSuper, path: &Path) -> RafsResult<Arc<dyn RafsInodeExt>> {
    let mut inode = rs.get_extended_inode(rs.superblock.root_ino(), false)?;
    for name in path.iter().skip(1) {
        inode = inode.get_child_by_name(name)?;
    }
    Ok(inode)
}

/// The number of regular file paths of the RAFS v6 image `rs` loaded from `bootstrap`, and the
/// page cache sharing fingerprint of each one the kernel reads exactly through its chunk-table
/// chunks ([`check_kernel_layout`]), computed from those chunks with
/// [`ishare_fingerprint`]. None at all when a blob's digest algorithm differs from the
/// image's: fills are validated with the blob's, which the fingerprint must name.
pub fn node_fingerprints(
    rs: &RafsSuper,
    bootstrap: &Path,
) -> RafsResult<(usize, HashMap<PathBuf, [u8; 32]>)> {
    let report = check_kernel_layout(rs, bootstrap)?;
    if !report.image_errors.is_empty() {
        return Err(RafsError::InvalidMetadata(format!(
            "the image fails the kernel layout check: {}",
            report.image_errors.join("; ")
        )));
    }
    let mut fingerprints = HashMap::new();
    let digester = rs.meta.get_digester();
    if let Some(blob) = rs
        .superblock
        .get_blob_infos()
        .iter()
        .find(|b| b.digester() != digester)
    {
        warn!(
            "blob {} uses digest {}, the image {}; not fingerprinting any file",
            blob.blob_id(),
            blob.digester(),
            digester
        );
        return Ok((report.files.len(), fingerprints));
    }
    for file in fit_files(&report) {
        let inode = inode_at(rs, &file.path)?;
        let chunks = (0..inode.get_chunk_count())
            .map(|i| {
                inode
                    .get_chunk_info(i)
                    .map(|c| (c.uncompressed_size(), c.chunk_id().data))
            })
            .collect::<RafsResult<Vec<_>>>()?;
        if let Some(fingerprint) = ishare_fingerprint(digester, inode.size(), chunks) {
            fingerprints.insert(file.path.clone(), fingerprint);
        }
    }
    Ok((report.files.len(), fingerprints))
}

/// Check that the fingerprints the kernel finds in the RAFS v6 image `rs` loaded from
/// `bootstrap` are exactly the ones [`node_fingerprints`] computes for it: the superblock names
/// the RAFS fingerprint prefix, every inode the computation fingerprints stores that value, and
/// no other inode stores any. Returns the number of fingerprinted paths.
///
/// This is what makes a node view built by a subprocess trustworthy: what the subprocess wrote
/// is compared with what this process derives from the view's own chunk table.
pub fn check_node_view(rs: &RafsSuper, bootstrap: &Path) -> RafsResult<usize> {
    let mismatch = |what: String| Err(RafsError::InvalidMetadata(what));
    let (_, want) = node_fingerprints(rs, bootstrap)?;
    let file = File::open(bootstrap)?;
    let mut sb = RafsV6SuperBlock::new();
    file.read_exact_at(sb.as_mut(), EROFS_SUPER_OFFSET as u64)?;
    if sb.has_ishare_xattrs() {
        let table = ishare_xattr_prefix_table();
        let mut stored = vec![0u8; table.len()];
        let offset = sb.xattr_prefix_table_offset().unwrap_or(u64::MAX);
        if sb.xattr_prefix_count() != 1
            || sb.ishare_xattr_prefix_id() != 0
            || file.read_exact_at(&mut stored, offset).is_err()
            || stored != table
        {
            return mismatch("the fingerprint prefix is not the RAFS one".to_string());
        }
    } else if !want.is_empty() {
        return mismatch("the image declares no fingerprints".to_string());
    }

    let root = rs.get_extended_inode(rs.superblock.root_ino(), false)?;
    let mut pending = vec![(PathBuf::from("/"), root)];
    while let Some((path, inode)) = pending.pop() {
        if inode.is_dir() {
            for idx in 0..inode.get_child_count() {
                let child = inode.get_child_by_index(idx)?;
                pending.push((path.join(child.name()), child));
            }
        }
        let ondisk = inode
            .as_any()
            .downcast_ref::<OndiskInodeWrapper>()
            .ok_or(RafsError::Unsupported)?;
        let stored = ondisk.ishare_fingerprint()?;
        let expected = want.get(&path).map(|f| f.to_vec());
        if stored != expected {
            return mismatch(format!(
                "{}: stored fingerprint {stored:02x?}, computed {expected:02x?}",
                path.display()
            ));
        }
    }
    Ok(want.len())
}

/// Check that the kernel reads RAFS chunk `idx` of `inode` exactly where the fill path writes it.
fn check_chunk(
    rs: &RafsSuper,
    inode: &OndiskInodeWrapper,
    idx: u32,
    kernel_bits: u32,
    devslots: &[RafsV6Device],
    device_id_mask: u16,
    overlapping: &HashSet<(u32, u32)>,
) -> Result<(), LayoutViolation> {
    let block_size = 1u64 << rs.meta.blkszbits;
    let chunk_size = rs.meta.chunk_size as u64;
    let unknown = LayoutViolation::UnknownChunk { chunk: idx };
    let chunk = inode.get_chunk_info(idx).map_err(|_| unknown.clone())?;
    let blob = chunk.blob_index();
    if rs
        .superblock
        .get_blob_infos()
        .get(blob as usize)
        .is_some_and(|b| b.has_feature(BlobFeatures::EXTERNAL))
    {
        return Err(LayoutViolation::ExternalBlob { chunk: idx, blob });
    }
    let file_offset = idx as u64 * chunk_size;
    let expected = chunk_size.min(inode.size() - file_offset);
    if chunk.uncompressed_size() as u64 != expected {
        return Err(LayoutViolation::ChunkSize {
            chunk: idx,
            size: chunk.uncompressed_size(),
            expected,
        });
    }
    // The kernel chunk covering this RAFS chunk; the same one unless the builder merged a
    // contiguous file into one kernel chunk.
    let kernel_idx = (file_offset >> kernel_bits) as u32;
    let addr = inode
        .get_chunk_addr(kernel_idx)
        .map_err(|_| unknown.clone())?;
    let device = addr.device_id() & device_id_mask;
    if device as u32 != blob + 1 {
        return Err(LayoutViolation::DeviceId {
            chunk: idx,
            device,
            blob,
        });
    }
    if addr.block_addr() == EROFS_NULL_ADDR {
        return Err(LayoutViolation::Hole { chunk: idx });
    }
    let kernel = addr.block_addr() as u64 * block_size
        + (file_offset - ((kernel_idx as u64) << kernel_bits));
    if kernel != chunk.uncompressed_offset() {
        return Err(LayoutViolation::BlockAddr {
            chunk: idx,
            kernel,
            uncompressed: chunk.uncompressed_offset(),
        });
    }
    let slot = devslots
        .get(blob as usize)
        .ok_or(LayoutViolation::MissingDevice { chunk: idx, blob })?;
    let end = (kernel + expected).div_ceil(block_size);
    if end > slot.blocks() as u64 {
        return Err(LayoutViolation::PastDevice {
            chunk: idx,
            end,
            blocks: slot.blocks() as u64,
        });
    }
    if overlapping.contains(&(blob, chunk.id())) {
        return Err(LayoutViolation::Overlap { chunk: idx, blob });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_api::ConfigV2;

    fn fixture() -> PathBuf {
        let root = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        PathBuf::from(root).join("../tests/texture/bootstrap/rafs-v6-2.2.boot")
    }

    fn load(path: &Path) -> RafsSuper {
        let config = ConfigV2 {
            metadata_source: crate::test_util::METADATA_SOURCE,
            ..Default::default()
        };
        RafsSuper::load_from_file(path, Arc::new(config), false)
            .unwrap()
            .0
    }

    /// The first chunk address of a regular file with data.
    fn first_chunk_addr(rs: &RafsSuper, report: &KernelLayoutReport) -> [u8; 8] {
        let file = report
            .files
            .iter()
            .find(|f| rs.get_inode(f.ino, false).unwrap().size() > 0)
            .unwrap();
        let inode = rs.get_inode(file.ino, false).unwrap();
        let ondisk = inode.as_any().downcast_ref::<OndiskInodeWrapper>().unwrap();
        let addr = ondisk.get_chunk_addr(0).unwrap();
        addr.as_ref().try_into().unwrap()
    }

    /// Write a copy of the fixture with the 8 bytes `from` replaced by `to`, everywhere.
    fn patched(dir: &Path, from: &[u8], to: &[u8]) -> PathBuf {
        let mut data = std::fs::read(fixture()).unwrap();
        let mut hits = 0;
        for i in 0..data.len() - from.len() {
            if &data[i..i + from.len()] == from {
                data[i..i + from.len()].copy_from_slice(to);
                hits += 1;
            }
        }
        assert!(hits > 0);
        let path = dir.join("patched.boot");
        std::fs::write(&path, data).unwrap();
        path
    }

    /// One violating path of a hardlink group takes the fingerprint from every path of it.
    #[test]
    fn a_hardlink_group_with_one_unfit_path_is_unfit() {
        let file = |ino, path: &str, violations| FileLayout {
            ino,
            path: PathBuf::from(path),
            violations,
        };
        let report = KernelLayoutReport {
            image_errors: Vec::new(),
            files: vec![
                file(1, "/a", Vec::new()),
                file(2, "/b", Vec::new()),
                file(2, "/b-link", vec![LayoutViolation::Hole { chunk: 0 }]),
                file(3, "/c", Vec::new()),
            ],
        };
        let fit: Vec<_> = fit_files(&report).map(|f| f.path.clone()).collect();
        assert_eq!(fit, vec![PathBuf::from("/a"), PathBuf::from("/c")]);
    }

    /// A builder image without fingerprints is a consistent view; one whose superblock declares
    /// fingerprints its inodes do not store is not.
    #[test]
    #[cfg_attr(miri, ignore = "reads the bootstrap through the file system")]
    fn check_node_view_compares_stored_fingerprints() {
        let rs = load(&fixture());
        let (files, want) = node_fingerprints(&rs, &fixture()).unwrap();
        assert!(files > 0);
        // The fixture has no fingerprints although its files could have them.
        assert!(!want.is_empty());
        assert!(check_node_view(&rs, &fixture()).is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the bootstrap through the file system")]
    fn a_builder_image_is_strict() {
        let rs = load(&fixture());
        let report = check_kernel_layout(&rs, &fixture()).unwrap();
        assert!(report.files.iter().any(|f| !f.path.as_os_str().is_empty()));
        assert!(report.is_strict(), "{report:#?}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the bootstrap through the file system")]
    fn a_moved_block_address_is_reported_for_its_file() {
        let rs = load(&fixture());
        let report = check_kernel_layout(&rs, &fixture()).unwrap();
        let from = first_chunk_addr(&rs, &report);
        // The chunk table lookup is keyed by the whole address, so moving it makes the chunk
        // unknown; the kernel would read other bytes.
        let mut to = from;
        to[4] ^= 1;
        let dir = tempfile::tempdir().unwrap();
        let path = patched(dir.path(), &from, &to);
        let rs = load(&path);
        let report = check_kernel_layout(&rs, &path).unwrap();
        assert!(!report.is_strict());
        assert!(report.files.iter().any(|f| {
            f.violations
                .iter()
                .any(|v| matches!(v, LayoutViolation::UnknownChunk { .. }))
        }));
        // Files that do not use the chunk stay strict.
        assert!(report.files.iter().any(|f| f.violations.is_empty()));
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the bootstrap through the file system")]
    fn a_chunk_shorter_than_the_kernel_reads_is_reported() {
        let rs = load(&fixture());
        let unit = size_of::<RafsV5ChunkInfo>();
        let table = rs.meta.chunk_table_offset as usize;
        let size_at = table + std::mem::offset_of!(RafsV5ChunkInfo, uncompressed_size);
        let mut data = std::fs::read(fixture()).unwrap();
        let size = u32::from_le_bytes(data[size_at..size_at + 4].try_into().unwrap());
        assert!(size > 1 && rs.meta.chunk_table_size as usize >= unit);
        data[size_at..size_at + 4].copy_from_slice(&(size - 1).to_le_bytes());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.boot");
        std::fs::write(&path, &data).unwrap();
        let rs = load(&path);
        let report = check_kernel_layout(&rs, &path).unwrap();
        assert!(report.files.iter().any(|f| {
            f.violations
                .iter()
                .any(|v| matches!(v, LayoutViolation::ChunkSize { .. }))
        }));
    }

    /// Two chunks of one blob starting at the same offset, each consistent with the inode that
    /// uses it: the fill path would validate only one of them for both files.
    #[test]
    #[cfg_attr(miri, ignore = "reads the bootstrap through the file system")]
    fn chunks_sharing_a_start_are_reported() {
        use super::super::layout::v6::RafsV6InodeChunkAddr;

        let rs = load(&fixture());
        let table = chunk_table(&rs).unwrap();
        let block_size = 1u64 << rs.meta.blkszbits;
        let (a, b) = table
            .iter()
            .find_map(|a| {
                table.iter().find_map(|b| {
                    (a.blob_index() == b.blob_index()
                        && a.id() != b.id()
                        && b.id() > 0
                        && b.uncompressed_offset() > 0
                        && a.uncompressed_offset() != b.uncompressed_offset())
                    .then(|| (a.clone(), b.clone()))
                })
            })
            .expect("two distinct chunks of one blob");
        let addr = |c: &Arc<dyn BlobChunkInfo>, offset: u64| {
            let mut addr = RafsV6InodeChunkAddr::new();
            addr.set_blob_index(c.blob_index());
            addr.set_blob_ci_index(c.id());
            addr.set_block_addr((offset / block_size) as u32);
            addr
        };
        let unit = size_of::<RafsV5ChunkInfo>();
        let field = |rec: usize, at: usize, data: &[u8]| {
            u32::from_le_bytes(data[rec + at..rec + at + 4].try_into().unwrap())
        };
        let offset_at = std::mem::offset_of!(RafsV5ChunkInfo, uncompressed_offset);
        let mut data = std::fs::read(fixture()).unwrap();
        // Move `b` onto `a`'s start, in the chunk table and in every inode that uses it.
        let base = rs.meta.chunk_table_offset as usize;
        let mut moved = 0;
        for i in 0..rs.meta.chunk_table_size as usize / unit {
            let rec = base + i * unit;
            if field(rec, std::mem::offset_of!(RafsV5ChunkInfo, index), &data) == b.id()
                && field(
                    rec,
                    std::mem::offset_of!(RafsV5ChunkInfo, blob_index),
                    &data,
                ) == b.blob_index()
            {
                data[rec + offset_at..rec + offset_at + 8]
                    .copy_from_slice(&a.uncompressed_offset().to_le_bytes());
                moved += 1;
            }
        }
        assert!(moved > 0);
        let from = addr(&b, b.uncompressed_offset());
        let to = addr(&b, a.uncompressed_offset());
        let mut hits = 0;
        for i in 0..data.len() - 8 {
            if &data[i..i + 8] == from.as_ref() {
                data[i..i + 8].copy_from_slice(to.as_ref());
                hits += 1;
            }
        }
        assert!(hits > 0);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared-start.boot");
        std::fs::write(&path, &data).unwrap();
        let rs = load(&path);
        let report = check_kernel_layout(&rs, &path).unwrap();
        assert!(
            report.files.iter().any(|f| f
                .violations
                .iter()
                .any(|v| matches!(v, LayoutViolation::Overlap { .. }))),
            "{report:#?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the bootstrap through the file system")]
    fn digest_tables_cover_every_referenced_chunk() {
        let rs = load(&fixture());
        let tables = chunk_digest_tables(&rs).unwrap();
        let blobs = rs.superblock.get_blob_infos();
        assert_eq!(tables.len(), blobs.len());
        for chunk in chunk_table(&rs).unwrap() {
            let entry = tables[chunk.blob_index() as usize][chunk.id() as usize].unwrap();
            assert_eq!(entry.digest, *chunk.chunk_id());
            assert_eq!(entry.uncompressed_offset, chunk.uncompressed_offset());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the bootstrap through the file system")]
    fn conflicting_digests_for_one_chunk_are_rejected() {
        let rs = load(&fixture());
        let unit = size_of::<RafsV5ChunkInfo>();
        let table = rs.meta.chunk_table_offset as usize;
        assert!(rs.meta.chunk_table_size as usize >= 2 * unit);
        // Give record 1 the blob and chunk index of record 0, keeping its own digest.
        let mut data = std::fs::read(fixture()).unwrap();
        let first = data[table..table + unit].to_vec();
        let second = &mut data[table + unit..table + 2 * unit];
        let digest = std::mem::offset_of!(RafsV5ChunkInfo, block_id);
        let digest_len = size_of::<nydus_utils::digest::RafsDigest>();
        second[digest + digest_len..].copy_from_slice(&first[digest + digest_len..]);
        assert_ne!(second[..digest_len], first[..digest_len]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dup.boot");
        std::fs::write(&path, &data).unwrap();
        let rs = load(&path);
        assert!(matches!(
            chunk_digest_tables(&rs),
            Err(RafsError::InvalidMetadata(_))
        ));
    }
}
