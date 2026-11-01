// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Validator for RAFS format

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use nydus_api::ConfigV2;
use nydus_builder::Tree;
use nydus_rafs::metadata::direct_v6::OndiskInodeWrapper;
use nydus_rafs::metadata::layout::v6::RafsV6Device;
use nydus_rafs::metadata::{RafsSuper, RafsVersion};
use nydus_storage::device::{BlobFeatures, BlobInfo};
use nydus_utils::compress;

pub struct Validator {
    sb: RafsSuper,
    path: PathBuf,
}

impl Validator {
    pub fn new(bootstrap_path: &Path, config: Arc<ConfigV2>) -> Result<Self> {
        let (sb, _) = RafsSuper::load_from_file(bootstrap_path, config, false)?;

        Ok(Self {
            sb,
            path: bootstrap_path.to_path_buf(),
        })
    }

    pub fn check(
        &mut self,
        verbosity: bool,
    ) -> Result<(Vec<Arc<BlobInfo>>, compress::Algorithm, RafsVersion)> {
        let err = "failed to load bootstrap for validator";
        let tree = Tree::from_bootstrap(&self.sb, &mut ()).context(err)?;

        let pre = &mut |t: &Tree| -> Result<()> {
            let node = t.borrow_mut_node();
            if verbosity {
                println!("inode: {}", node);
                for chunk in &node.chunks {
                    println!("\t chunk: {}", chunk);
                }
            }
            Ok(())
        };
        tree.walk_dfs_pre(pre)?;
        let compressor = self.sb.meta.get_compressor();
        let rafs_version: RafsVersion = self.sb.meta.version.try_into().unwrap();
        if rafs_version == RafsVersion::V6 {
            self.check_v6_block_addrs()?;
        }

        Ok((
            self.sb.superblock.get_blob_infos(),
            compressor,
            rafs_version,
        ))
    }

    /// The kernel reads a chunk at `block_addr * block_size` of the device its chunk address
    /// names, while FUSE reads it at the chunk table's uncompressed offset. Both must agree and
    /// the chunk must lie inside the device slot, or only a kernel mount reads the wrong bytes.
    fn check_v6_block_addrs(&self) -> Result<()> {
        let meta = &self.sb.meta;
        let mut devslots = vec![RafsV6Device::new(); meta.blob_device_table_count as usize];
        if devslots.is_empty() {
            return Ok(());
        }
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(meta.blob_device_table_offset))?;
        for devslot in devslots.iter_mut() {
            f.read_exact(devslot.as_mut())
                .context("failed to read the device table")?;
        }
        let blobs = self.sb.superblock.get_blob_infos();
        let block_size = 1u64 << meta.blkszbits;

        // `Tree::from_bootstrap` has already rejected directory cycles.
        let root = self
            .sb
            .get_extended_inode(self.sb.superblock.root_ino(), false)?;
        let mut pending = vec![(PathBuf::from("/"), root)];
        while let Some((path, inode)) = pending.pop() {
            if inode.is_dir() {
                for idx in 0..inode.get_child_count() {
                    let child = inode.get_child_by_index(idx)?;
                    pending.push((path.join(child.name()), child));
                }
                continue;
            }
            let Some(ondisk) = inode.as_any().downcast_ref::<OndiskInodeWrapper>() else {
                continue;
            };
            for idx in 0..inode.get_chunk_count() {
                let addr = ondisk.get_chunk_addr(idx)?;
                let chunk = inode.get_chunk_info(idx)?;
                let blob_index = addr.blob_index()? as usize;
                // External blobs are not EROFS devices, so their chunks carry no usable blkaddr.
                if blobs
                    .get(blob_index)
                    .is_some_and(|b| b.has_feature(BlobFeatures::EXTERNAL))
                {
                    continue;
                }
                let devslot = devslots.get(blob_index).with_context(|| {
                    format!(
                        "{}: chunk {idx} names device {blob_index}, which the device table lacks",
                        path.display()
                    )
                })?;
                let start = addr.block_addr() as u64 * block_size;
                ensure!(
                    start == chunk.uncompressed_offset(),
                    "{}: chunk {idx} is at block address 0x{:x} (offset 0x{start:x}) but its data starts at uncompressed offset 0x{:x}",
                    path.display(),
                    addr.block_addr(),
                    chunk.uncompressed_offset()
                );
                let end = addr.block_addr() as u64
                    + (chunk.uncompressed_size() as u64).div_ceil(block_size);
                ensure!(
                    end <= devslot.blocks() as u64,
                    "{}: chunk {idx} ends at block 0x{end:x}, past the {} blocks of device {blob_index}",
                    path.display(),
                    devslot.blocks()
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;

    fn create_test_config(blob_dir: &str) -> Arc<ConfigV2> {
        let content = format!(
            r#"{{
                "version": 2,
                "id": "validator-test",
                "backend": {{
                    "type": "localfs",
                    "localfs": {{
                        "dir": "{}"
                    }}
                }},
                "cache": {{
                    "type": "filecache",
                    "filecache": {{
                        "work_dir": "{}"
                    }}
                }}
            }}"#,
            blob_dir, blob_dir
        );
        Arc::new(serde_json::from_str(&content).unwrap())
    }

    fn prepare_fixture_root() -> (vmm_sys_util::tempdir::TempDir, PathBuf) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let root_dir = std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let fixture_blob = PathBuf::from(&root_dir).join(
            "tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef",
        );
        let target_blob = tmp_dir
            .as_path()
            .join("be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        fs::copy(fixture_blob, target_blob).unwrap();

        let bootstrap = PathBuf::from(root_dir).join("tests/texture/bootstrap/rafs-v6-2.2.boot");
        (tmp_dir, bootstrap)
    }

    #[test]
    fn test_validator_new_rejects_invalid_bootstrap() {
        let config = create_test_config("/tmp");
        assert!(Validator::new(Path::new("/does/not/exist"), config).is_err());
    }

    #[test]
    fn test_validator_check_returns_blob_metadata() {
        let (tmp_dir, bootstrap) = prepare_fixture_root();
        let config = create_test_config(tmp_dir.as_path().to_str().unwrap());

        let mut validator = Validator::new(&bootstrap, config).unwrap();
        let (blobs, compressor, rafs_version) = validator.check(false).unwrap();

        assert_eq!(blobs.len(), 1);
        assert_eq!(
            blobs[0].raw_blob_id(),
            "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef"
        );
        assert!(!blobs[0].blob_id().is_empty());
        assert_eq!(compressor, compress::Algorithm::Zstd);
        assert_eq!(rafs_version, RafsVersion::V6);
    }

    // Builds a two-file RAFS v6 image at `block_size`; returns (blob dir, bootstrap path).
    fn build_image(block_size: u64) -> (vmm_sys_util::tempdir::TempDir, PathBuf) {
        use nydus_builder::{
            ArtifactStorage, BlobManager, BootstrapManager, BuildContext, Builder, ConversionType,
            DirectoryBuilder,
        };

        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source = dir.as_path().join("src");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("a"), vec![1u8; 5000]).unwrap();
        fs::write(source.join("b"), vec![2u8; 20000]).unwrap();
        let bootstrap = dir.as_path().join("bootstrap");
        let mut ctx = BuildContext {
            fs_version: RafsVersion::V6,
            conversion_type: ConversionType::DirectoryToRafs,
            source_path: source,
            aligned_chunk: true,
            blob_storage: Some(ArtifactStorage::FileDir((
                dir.as_path().to_path_buf(),
                String::new(),
            ))),
            ..Default::default()
        };
        ctx.set_blob_block_size(block_size);
        let mut bootstrap_mgr =
            BootstrapManager::new(Some(ArtifactStorage::SingleFile(bootstrap.clone())), None);
        let mut blob_mgr = BlobManager::new(ctx.digester, false);
        DirectoryBuilder::new()
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
        (dir, bootstrap)
    }

    fn check_image(dir: &vmm_sys_util::tempdir::TempDir, bootstrap: &Path) -> Result<()> {
        let config = create_test_config(dir.as_path().to_str().unwrap());
        Validator::new(bootstrap, config)?.check(false).map(|_| ())
    }

    // Moves the chunk table's uncompressed offset of the 20000-byte "b" by 512 bytes, leaving
    // the chunk address the kernel follows unchanged. The loader matches chunk addresses by
    // `offset / block_size`, so it still finds the chunk. In a `RafsV5ChunkInfo` the
    // uncompressed offset sits 12 bytes after the uncompressed size.
    fn shift_chunk_offset(path: &Path, offset: u64) {
        let mut data = fs::read(path).unwrap();
        let hits: Vec<usize> = (0..data.len().saturating_sub(20))
            .filter(|&i| {
                data[i..i + 4] == 20000u32.to_le_bytes()
                    && data[i + 12..i + 20] == offset.to_le_bytes()
            })
            .collect();
        assert_eq!(hits.len(), 1, "chunk info of b must occur exactly once");
        data[hits[0] + 12..hits[0] + 20].copy_from_slice(&(offset + 512).to_le_bytes());
        fs::write(path, data).unwrap();
    }

    #[test]
    fn test_validator_checks_v6_block_addresses() {
        for block_size in [4096u64, 16384] {
            let (dir, bootstrap) = build_image(block_size);
            check_image(&dir, &bootstrap).unwrap();

            // "b" follows the 5000-byte "a", padded to a block. The kernel still reads it at
            // its block address, FUSE now 512 bytes further.
            shift_chunk_offset(&bootstrap, 5000u64.next_multiple_of(block_size));
            let err = check_image(&dir, &bootstrap).unwrap_err();
            assert!(
                format!("{err:#}").contains("but its data starts at uncompressed offset"),
                "{err:#}"
            );

            // A device slot too short for the chunks it holds.
            let (dir, bootstrap) = build_image(block_size);
            let (sb, _) = RafsSuper::load_from_file(
                &bootstrap,
                create_test_config(dir.as_path().to_str().unwrap()),
                false,
            )
            .unwrap();
            let blocks_off = sb.meta.blob_device_table_offset as usize + 64;
            let mut data = fs::read(&bootstrap).unwrap();
            data[blocks_off..blocks_off + 4].copy_from_slice(&1u32.to_le_bytes());
            fs::write(&bootstrap, data).unwrap();
            let err = check_image(&dir, &bootstrap).unwrap_err();
            assert!(format!("{err:#}").contains("past the 1 blocks"), "{err:#}");
        }
    }
}
