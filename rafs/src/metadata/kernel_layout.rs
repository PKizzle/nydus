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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nydus_storage::device::{BlobChunkInfo, BlobFeatures, ChunkDigestEntry};

use super::direct_v6::OndiskInodeWrapper;
use super::layout::v5::RafsV5ChunkInfo;
use super::layout::v6::{
    EROFS_CHUNK_FORMAT_INDEXES_FLAG, EROFS_CHUNK_FORMAT_SIZE_MASK, EROFS_INODE_CHUNK_BASED,
    RafsV6Device,
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

    let mut extents: HashMap<u32, BTreeMap<u64, (u32, u64)>> = HashMap::new();
    for chunk in chunk_table(rs)? {
        let end = chunk.uncompressed_offset() + chunk.uncompressed_size() as u64;
        extents
            .entry(chunk.blob_index())
            .or_default()
            .insert(chunk.uncompressed_offset(), (chunk.id(), end));
    }
    let mut overlapping: HashSet<(u32, u32)> = HashSet::new();
    for (blob, by_offset) in &extents {
        let mut prev: Option<(u32, u64)> = None;
        for (start, (ci, end)) in by_offset {
            if let Some((prev_ci, prev_end)) = prev
                && *start < prev_end
            {
                overlapping.insert((*blob, prev_ci));
                overlapping.insert((*blob, *ci));
            }
            if prev.is_none_or(|(_, e)| *end > e) {
                prev = Some((*ci, *end));
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
