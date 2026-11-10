// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Validator for RAFS format

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use nydus_api::ConfigV2;
use nydus_builder::Tree;
use nydus_rafs::metadata::{RafsSuper, RafsVersion};
use nydus_storage::device::BlobInfo;
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
            self.sb.check_v6_block_addrs(&self.path)?;
        }

        Ok((
            self.sb.superblock.get_blob_infos(),
            compressor,
            rafs_version,
        ))
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

    fn prepare_fixture_root() -> (tempfile::TempDir, PathBuf) {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let root_dir = std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let fixture_blob = PathBuf::from(&root_dir).join(
            "tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef",
        );
        let target_blob = tmp_dir
            .path()
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
    #[cfg_attr(miri, ignore = "Miri does not support copy_file_range")]
    fn test_validator_check_returns_blob_metadata() {
        let (tmp_dir, bootstrap) = prepare_fixture_root();
        let config = create_test_config(tmp_dir.path().to_str().unwrap());

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

    // Builds a RAFS v6 image of two files and a symlink at `block_size`; returns (blob dir,
    // bootstrap path).
    fn build_image(
        block_size: u64,
        compressor: compress::Algorithm,
    ) -> (tempfile::TempDir, PathBuf) {
        use nydus_builder::{
            ArtifactStorage, BlobManager, BootstrapManager, BuildContext, Builder, ConversionType,
            DirectoryBuilder,
        };

        let dir = tempfile::TempDir::new().unwrap();
        let source = dir.path().join("src");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("a"), vec![1u8; 5000]).unwrap();
        fs::write(source.join("b"), vec![2u8; 20000]).unwrap();
        std::os::unix::fs::symlink("a", source.join("link")).unwrap();
        let bootstrap = dir.path().join("bootstrap");
        let mut ctx = BuildContext {
            fs_version: RafsVersion::V6,
            conversion_type: ConversionType::DirectoryToRafs,
            source_path: source,
            aligned_chunk: true,
            compressor,
            blob_storage: Some(ArtifactStorage::FileDir((
                dir.path().to_path_buf(),
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

    fn check_image(dir: &tempfile::TempDir, bootstrap: &Path) -> Result<()> {
        let config = create_test_config(dir.path().to_str().unwrap());
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

    // The layout `nydusify convert` produces by default: compressed chunks and a symlink.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support xattrs")]
    fn test_validator_accepts_compressed_image() {
        for block_size in [4096u64, 16384] {
            let (dir, bootstrap) = build_image(block_size, compress::Algorithm::Zstd);
            check_image(&dir, &bootstrap).unwrap();
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support xattrs")]
    fn test_validator_checks_v6_block_addresses() {
        for block_size in [4096u64, 16384] {
            let (dir, bootstrap) = build_image(block_size, compress::Algorithm::None);
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
            let (dir, bootstrap) = build_image(block_size, compress::Algorithm::None);
            let (sb, _) = RafsSuper::load_from_file(
                &bootstrap,
                create_test_config(dir.path().to_str().unwrap()),
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
