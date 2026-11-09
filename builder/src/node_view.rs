// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! The node view of a RAFS v6 image: a metadata-only bootstrap the node builds itself from any
//! image's bootstrap, to mount with EROFS page cache sharing (`inode_share`).
//!
//! The kernel shares one page cache between files of a domain whose fingerprint xattrs are equal
//! and never compares their contents, so every fingerprint in a domain must be computed by the
//! node. The view keeps the source's tree, xattrs and chunk table but nothing the source claims
//! about sharing: RAFS readers skip long-prefix xattrs, the only form a fingerprint has on disk,
//! so a shipped fingerprint never reaches the view. Each regular file whose kernel reading the
//! view provably confines to its own chunk-table chunks
//! ([`check_kernel_layout`](nydus_rafs::metadata::kernel_layout::check_kernel_layout)) gets
//! [`ishare_fingerprint`] computed from those very chunks; any other file gets none and only
//! misses out on sharing.
//!
//! The view uses 4 KiB blocks, which every page size admits, with device slots sized for that
//! block size. A v6 builder places every chunk at a multiple of its own block size (at least
//! 4 KiB), so a 16 KiB or 64 KiB source keeps its chunk addresses exact at 4 KiB. No layer data
//! is read: chunk digests and extents come from the source bootstrap's chunk table.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use nydus_api::ConfigV2;
use nydus_rafs::metadata::kernel_layout::check_kernel_layout;
use nydus_rafs::metadata::layout::v6::{EROFS_BLOCK_SIZE_4096, ishare_fingerprint};
use nydus_rafs::metadata::{RafsSuper, RafsVersion};
use nydus_utils::crypt;

use super::{
    ArtifactStorage, BlobContext, BlobManager, Bootstrap, BootstrapContext, BuildContext,
    ChunkSource, Tree,
};

/// What [`build_node_view`] wrote.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeView {
    /// Paths of regular files in the view, hardlinks included.
    pub regular_files: usize,
    /// Those of them that carry a node-computed fingerprint.
    pub fingerprinted: usize,
}

/// Write the node view of the RAFS v6 bootstrap `source` to `target`.
///
/// Fails, leaving `target` in no defined state, for a v5, tarfs or encrypted source, for one the
/// builder cannot lay out at 4 KiB blocks, or for a view whose device table is not what the
/// kernel reads. The caller then serves the source as it is, without sharing.
pub fn build_node_view(source: &Path, target: &Path, config: Arc<ConfigV2>) -> Result<NodeView> {
    let (rs, _) = RafsSuper::load_from_file(source, config.clone(), false)
        .with_context(|| format!("failed to load bootstrap {}", source.display()))?;
    ensure!(
        rs.meta.is_v6(),
        "{} is a RAFS v5 bootstrap, which EROFS cannot mount",
        source.display()
    );
    ensure!(
        !rs.meta.get_config().is_tarfs_mode,
        "{} is a tarfs bootstrap",
        source.display()
    );
    if rs.meta.get_cipher() != crypt::Algorithm::None {
        bail!("{} is encrypted", source.display());
    }

    // The fingerprints are computed from the view as written, so a first pass lays it out
    // without any; the second adds them, which moves inodes but no chunk.
    dump_view(&rs, target, &HashMap::new())?;
    let (regular_files, fingerprints) = node_fingerprints(target, config.clone())?;
    dump_view(&rs, target, &fingerprints)?;
    let (_, written) = node_fingerprints(target, config)?;
    ensure!(
        written == fingerprints,
        "the fingerprinted view of {} reads differently from its plain layout",
        source.display()
    );
    Ok(NodeView {
        regular_files,
        fingerprinted: fingerprints.len(),
    })
}

/// Dump the source's tree as a 4 KiB-block v6 bootstrap at `target`, with the blob table and
/// blob ids of the source, giving each path in `fingerprints` its fingerprint.
fn dump_view(
    rs: &RafsSuper,
    target: &Path,
    fingerprints: &HashMap<PathBuf, [u8; 32]>,
) -> Result<()> {
    let mut ctx = BuildContext {
        fs_version: RafsVersion::V6,
        compressor: rs.meta.get_compressor(),
        digester: rs.meta.get_digester(),
        explicit_uidgid: rs.meta.explicit_uidgid(),
        has_xattr: rs.meta.has_xattr(),
        chunk_size: rs.meta.chunk_size,
        ..Default::default()
    };
    ctx.set_blob_block_size(EROFS_BLOCK_SIZE_4096);

    // Chunks keep their blob indexes, so the blob table keeps its order, unreferenced blobs too.
    let mut blob_mgr = BlobManager::new(ctx.digester, false);
    for blob in rs.superblock.get_blob_infos() {
        let mut blob_ctx = BlobContext::from(&ctx, &blob, ChunkSource::Parent)?;
        blob_ctx.blob_id = blob.blob_id();
        blob_mgr.add_blob(blob_ctx);
    }

    let tree = Tree::from_bootstrap(rs, &mut ())?;
    for (path, fingerprint) in fingerprints {
        let node = tree
            .get_node(path)
            .with_context(|| format!("{} is not in the source tree", path.display()))?;
        Arc::make_mut(&mut node.borrow_mut_node().info)
            .xattrs
            .set_ishare_fingerprint(fingerprint.to_vec());
    }

    let storage = ArtifactStorage::SingleFile(target.to_path_buf());
    let mut bootstrap_ctx =
        BootstrapContext::new(Some(storage.clone()), false, ctx.v6_block_size())?;
    let mut bootstrap = Bootstrap::new(tree)?;
    bootstrap.build(&mut ctx, &mut bootstrap_ctx)?;
    let blob_table = blob_mgr.to_blob_table(&ctx)?;
    bootstrap
        .dump(
            &mut ctx,
            &mut Some(storage),
            &mut bootstrap_ctx,
            &blob_table,
        )
        .with_context(|| format!("failed to dump the node view to {}", target.display()))
}

/// The number of regular file paths of the bootstrap at `path`, and the fingerprint of each one
/// the kernel reads exactly through its chunk-table chunks, computed from those chunks.
fn node_fingerprints(
    path: &Path,
    config: Arc<ConfigV2>,
) -> Result<(usize, HashMap<PathBuf, [u8; 32]>)> {
    let (rs, _) = RafsSuper::load_from_file(path, config, false)
        .with_context(|| format!("failed to load the node view {}", path.display()))?;
    let report = check_kernel_layout(&rs, path)?;
    ensure!(
        report.image_errors.is_empty(),
        "the node view fails the kernel layout check: {}",
        report.image_errors.join("; ")
    );
    let mut fingerprints = HashMap::new();
    // Fills are validated with each blob's own algorithm, which the fingerprint must name.
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
    // Hardlinks share an inode, so one violating path rules out all of them.
    let unfit: HashSet<u64> = report
        .files
        .iter()
        .filter(|f| !f.violations.is_empty())
        .map(|f| f.ino)
        .collect();
    for file in report.files.iter().filter(|f| !unfit.contains(&f.ino)) {
        let mut inode = rs.get_extended_inode(rs.superblock.root_ino(), false)?;
        for name in file.path.iter().skip(1) {
            inode = inode.get_child_by_name(name)?;
        }
        let chunks = (0..inode.get_chunk_count())
            .map(|i| {
                inode
                    .get_chunk_info(i)
                    .map(|c| (c.uncompressed_size(), c.chunk_id().data))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(fingerprint) = ishare_fingerprint(digester, inode.size(), chunks) {
            fingerprints.insert(file.path.clone(), fingerprint);
        }
    }
    Ok((report.files.len(), fingerprints))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;

    use nydus_rafs::metadata::layout::v6::{EROFS_SUPER_OFFSET, RafsV6SuperBlock};
    use nydus_utils::digest::{self, RafsDigest};
    use tempfile::TempDir;

    use super::*;
    use crate::{ArtifactStorage, Builder, ConversionType, DirectoryBuilder, Merger};

    /// Build one RAFS v6 layer with `block_size` blocks from `files` (path, content) into `out`
    /// and return its bootstrap, named by the blob id merge gives it.
    fn layer(files: &[(&str, &[u8])], out: &Path, block_size: u64) -> PathBuf {
        let source = TempDir::new().unwrap();
        for (path, content) in files {
            let p = source.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }
        let bootstrap = out.join("cd".repeat(32));
        let mut ctx = BuildContext {
            fs_version: RafsVersion::V6,
            conversion_type: ConversionType::DirectoryToRafs,
            source_path: source.path().to_path_buf(),
            aligned_chunk: true,
            blob_storage: Some(ArtifactStorage::FileDir((out.to_path_buf(), String::new()))),
            ..Default::default()
        };
        ctx.set_blob_block_size(block_size);
        let mut bootstrap_mgr = crate::BootstrapManager::new(
            Some(ArtifactStorage::SingleFile(bootstrap.clone())),
            None,
        );
        let mut blob_mgr = BlobManager::new(ctx.digester, false);
        DirectoryBuilder::new()
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
        bootstrap
    }

    fn load(path: &Path) -> RafsSuper {
        RafsSuper::load_from_file(path, crate::test_config(), false)
            .unwrap()
            .0
    }

    fn view_of(source: &Path) -> (PathBuf, NodeView, TempDir) {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("view");
        let view = build_node_view(source, &target, crate::test_config()).unwrap();
        (target, view, dir)
    }

    /// Fingerprints of the view at `path`, by path, as the kernel layout check admits them.
    fn fingerprints(path: &Path) -> HashMap<PathBuf, [u8; 32]> {
        node_fingerprints(path, crate::test_config()).unwrap().1
    }

    /// Every fingerprint value stored in the bootstrap at `path`: the 32-byte values of
    /// xattr entries naming long prefix 0 with an empty suffix.
    fn stored_fingerprints(path: &Path) -> Vec<[u8; 32]> {
        let data = std::fs::read(path).unwrap();
        let entry = [0u8, 0x80, 32, 0];
        (0..data.len().saturating_sub(36))
            .filter(|&i| data[i..i + 4] == entry)
            .map(|i| data[i + 4..i + 36].try_into().unwrap())
            .collect()
    }

    fn has_ishare(path: &Path) -> bool {
        let mut sb = RafsV6SuperBlock::new();
        std::fs::File::open(path)
            .unwrap()
            .read_exact_at(sb.as_mut(), EROFS_SUPER_OFFSET as u64)
            .unwrap();
        sb.has_ishare_xattrs()
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support xattrs")]
    fn equal_content_gets_equal_fingerprints_across_images() {
        let lib: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut patched = lib.clone();
        patched[2_500_000] ^= 1;
        let (dir_a, dir_b) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let a = layer(
            &[
                ("usr/lib/libx.so", &lib),
                ("a", b"only in a"),
                ("empty", b""),
            ],
            dir_a.path(),
            4096,
        );
        let b = layer(
            &[("opt/libx.so", &lib), ("patched.so", &patched)],
            dir_b.path(),
            4096,
        );
        let (va, view_a, _ta) = view_of(&a);
        let (vb, _, _tb) = view_of(&b);
        assert_eq!(
            view_a,
            NodeView {
                regular_files: 3,
                fingerprinted: 2
            }
        );
        let (fa, fb) = (fingerprints(&va), fingerprints(&vb));
        let lib_fp = fa[Path::new("/usr/lib/libx.so")];
        assert_eq!(fb[Path::new("/opt/libx.so")], lib_fp);
        assert_ne!(fb[Path::new("/patched.so")], lib_fp);
        assert!(!fa.contains_key(Path::new("/empty")));
        // What is stored is exactly what the node computed.
        let mut stored = stored_fingerprints(&va);
        let mut computed: Vec<_> = fa.values().copied().collect();
        stored.sort();
        computed.sort();
        assert_eq!(stored, computed);
        assert!(has_ishare(&va));

        // The view keeps the blob table and reads the same files.
        let (sa, rva) = (load(&a), load(&va));
        assert_eq!(rva.meta.blkszbits, 12);
        let ids = |rs: &RafsSuper| -> Vec<String> {
            rs.superblock
                .get_blob_infos()
                .iter()
                .map(|b| b.blob_id())
                .collect()
        };
        assert_eq!(ids(&sa), ids(&rva));
        let root = rva.get_inode(rva.superblock.root_ino(), false).unwrap();
        assert!(
            root.get_child_by_name(std::ffi::OsStr::new("a"))
                .unwrap()
                .get_xattrs()
                .unwrap()
                .is_empty()
        );
    }

    /// The scheme names the digest algorithm: equal digests under different algorithms differ.
    #[test]
    fn the_fingerprint_names_the_algorithm_and_covers_the_file() {
        let chunks = [(4096u32, [7u8; 32]), (100, [8u8; 32])];
        let sha = ishare_fingerprint(digest::Algorithm::Sha256, 4196, chunks).unwrap();
        let blake = ishare_fingerprint(digest::Algorithm::Blake3, 4196, chunks).unwrap();
        assert_ne!(sha, blake);
        assert_eq!(
            ishare_fingerprint(digest::Algorithm::Sha256, 4196, chunks),
            Some(sha)
        );
        assert!(ishare_fingerprint(digest::Algorithm::Sha256, 4197, chunks).is_none());
        assert!(ishare_fingerprint(digest::Algorithm::Sha256, 0, []).is_none());
        assert!(ishare_fingerprint(digest::Algorithm::Sha256, 4096, [(4096, [0u8; 32])]).is_none());
    }

    /// A source cannot choose a view's fingerprints: a forged copy of another image's
    /// fingerprint in its bootstrap is dropped, and the file gets the one its chunks give it.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support xattrs")]
    fn a_shipped_fingerprint_is_ignored() {
        let dir = TempDir::new().unwrap();
        let merged = |files: &[(&str, &[u8])], name: &str| {
            let out = dir.path().join(name);
            std::fs::create_dir(&out).unwrap();
            let source = layer(files, &out, 4096);
            let target = out.join("merged");
            let mut ctx = BuildContext {
                inode_share_fingerprint: true,
                ..Default::default()
            };
            Merger::merge(
                &mut ctx,
                None,
                vec![source],
                None,
                Some(vec!["cd".repeat(32)]),
                None,
                None,
                None,
                ArtifactStorage::SingleFile(target.clone()),
                None,
                crate::test_config(),
            )
            .unwrap();
            target
        };
        let victim = merged(&[("lib.so", &[1u8; 9000])], "victim");
        let attacker = merged(&[("lib.so", &[2u8; 9000])], "attacker");
        let [victim_fp] = stored_fingerprints(&victim)[..] else {
            panic!("one fingerprint expected")
        };
        let mut forged = std::fs::read(&attacker).unwrap();
        let [own] = stored_fingerprints(&attacker)[..] else {
            panic!("one fingerprint expected")
        };
        let at = forged.windows(32).position(|w| w == own).unwrap();
        forged[at..at + 32].copy_from_slice(&victim_fp);
        std::fs::write(&attacker, forged).unwrap();
        assert_eq!(stored_fingerprints(&attacker), vec![victim_fp]);

        let (view, _, _t) = view_of(&attacker);
        let stored = stored_fingerprints(&view);
        assert_eq!(stored.len(), 1);
        assert_ne!(stored[0], victim_fp);
        assert_eq!(stored[0], fingerprints(&view)[Path::new("/lib.so")]);
        let (victim_view, _, _v) = view_of(&victim);
        assert_eq!(stored_fingerprints(&victim_view), vec![victim_fp]);
    }

    /// A file the kernel would not read through its own chunk-table chunks gets no fingerprint;
    /// the rest of the image still does.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support xattrs")]
    fn a_file_failing_the_layout_check_is_not_fingerprinted() {
        let dir = TempDir::new().unwrap();
        let f = vec![3u8; 9000];
        let source = layer(&[("f", &f), ("g", &[4u8; 5000])], dir.path(), 4096);
        let (view, _, _t) = view_of(&source);
        assert_eq!(fingerprints(&view).len(), 2);

        // Move f's chunk in the chunk table, past every other chunk: the kernel would read it elsewhere.
        let digest = RafsDigest::from_buf(&f, load(&source).meta.get_digester());
        let mut data = std::fs::read(&view).unwrap();
        let at = data.windows(32).position(|w| w == digest.data).unwrap();
        let offset = u64::from_le_bytes(data[at + 56..at + 64].try_into().unwrap());
        data[at + 56..at + 64].copy_from_slice(&(offset + (1 << 20)).to_le_bytes());
        std::fs::write(&view, data).unwrap();
        let left = fingerprints(&view);
        assert!(!left.contains_key(Path::new("/f")));
        assert!(left.contains_key(Path::new("/g")));
    }

    /// A 16 KiB-block image becomes a 4 KiB-block view the kernel reads exactly.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support xattrs")]
    fn a_16k_block_source_gets_an_exact_4k_view() {
        let dir = TempDir::new().unwrap();
        let source = layer(
            &[("a", &[1u8; 5000]), ("b", &[2u8; 40000])],
            dir.path(),
            16384,
        );
        assert_eq!(load(&source).meta.blkszbits, 14);
        let (view, summary, _t) = view_of(&source);
        let rs = load(&view);
        assert_eq!(rs.meta.blkszbits, 12);
        let report = check_kernel_layout(&rs, &view).unwrap();
        assert!(report.is_strict(), "{report:#?}");
        assert_eq!(summary.fingerprinted, 2);
        rs.check_v6_block_addrs(&view).unwrap();
    }
}
