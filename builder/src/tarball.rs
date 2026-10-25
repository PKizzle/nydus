// Copyright 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Generate RAFS filesystem from a tarball.
//!
//! It support generating RAFS filesystem from a tar/targz/stargz file with or without data blob.
//!
//! The tarball data is arrange as a sequence of tar headers with associated file data interleaved.
//! - (tar header) (tar header) (file data) (tar header) (file data) (tar header)
//!   And to support read tarball data from FIFO, we could only go over the tarball stream once.
//!   So the workflow is as:
//! - for each tar header from the stream
//!   -- generate RAFS filesystem node from the tar header
//!   -- optionally dump file data associated with the tar header into RAFS data blob
//! - arrange all generated RAFS nodes into a RAFS filesystem tree
//! - dump the RAFS filesystem tree into RAFS metadata blob
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use tar::{EntryType, Header};

use nydus_rafs::metadata::RafsVersion;
use nydus_rafs::metadata::inode::{InodeWrapper, RafsInodeFlags, RafsV6Inode};
use nydus_rafs::metadata::layout::RafsXAttrs;
use nydus_rafs::metadata::layout::v5::RafsV5Inode;
use nydus_storage::RAFS_MAX_CHUNKS_PER_BLOB;
use nydus_storage::device::BlobFeatures;
use nydus_storage::meta::ZranContextGenerator;
use nydus_utils::compact::makedev;
use nydus_utils::compress::ZlibDecoder;
use nydus_utils::compress::zlib_random::{ZRAN_READER_BUF_SIZE, ZranReader};
use nydus_utils::digest::RafsDigest;
use nydus_utils::{BufReaderInfo, ByteSize, div_round_up, lazy_drop, root_tracer, timing_tracer};

use crate::core::context::{Artifact, NoopArtifactWriter};

use super::core::blob::Blob;
use super::core::context::{
    ArtifactWriter, BlobManager, BootstrapManager, BuildContext, BuildOutput, ConversionType,
};
use super::core::node::{Node, NodeInfo};
use super::core::tree::Tree;
use super::tar_reader::{Member, Members};
use super::{Builder, TarBuilder, build_bootstrap, dump_bootstrap, finalize_blob};

enum CompressionType {
    None,
    Gzip,
}

enum TarReader {
    File(File),
    BufReader(BufReader<File>),
    BufReaderInfo(BufReaderInfo<File>),
    BufReaderInfoSeekable(BufReaderInfo<File>),
    TarGzFile(Box<ZlibDecoder<File>>),
    TarGzBufReader(Box<ZlibDecoder<BufReader<File>>>),
    ZranReader(ZranReader<File>),
}

impl Read for TarReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TarReader::File(f) => f.read(buf),
            TarReader::BufReader(f) => f.read(buf),
            TarReader::BufReaderInfo(b) => b.read(buf),
            TarReader::BufReaderInfoSeekable(b) => b.read(buf),
            TarReader::TarGzFile(f) => f.read(buf),
            TarReader::TarGzBufReader(b) => b.read(buf),
            TarReader::ZranReader(f) => f.read(buf),
        }
    }
}

impl TarReader {
    fn seekable(&self) -> bool {
        matches!(
            self,
            TarReader::File(_) | TarReader::BufReaderInfoSeekable(_)
        )
    }
}

impl Seek for TarReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            TarReader::File(f) => f.seek(pos),
            TarReader::BufReaderInfoSeekable(b) => b.seek(pos),
            // `Seek` is pinned to `io::Error` by std, but the message survives here --
            // the old error macro dropped it and answered a bare ENOSYS.
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TarReader: seek() is not supported for this reader",
            )),
        }
    }
}

struct TarballTreeBuilder<'a> {
    ty: ConversionType,
    ctx: &'a mut BuildContext,
    blob_mgr: &'a mut BlobManager,
    blob_writer: &'a mut dyn Artifact,
    buf: Vec<u8>,
    builder: TarBuilder,
}

impl<'a> TarballTreeBuilder<'a> {
    /// Create a new instance of `TarballBuilder`.
    pub fn new(
        ty: ConversionType,
        ctx: &'a mut BuildContext,
        blob_mgr: &'a mut BlobManager,
        blob_writer: &'a mut dyn Artifact,
        layer_idx: u16,
    ) -> Self {
        let builder = TarBuilder::new(ctx.explicit_uidgid, layer_idx, ctx.fs_version);
        Self {
            ty,
            ctx,
            blob_mgr,
            buf: Vec::new(),
            blob_writer,
            builder,
        }
    }

    fn build_tree(&mut self) -> Result<Tree> {
        let file = OpenOptions::new()
            .read(true)
            .open(self.ctx.source_path.clone())
            .context("tarball: can not open source file for conversion")?;
        let mut is_file = match file.metadata() {
            Ok(md) => md.file_type().is_file(),
            Err(_) => false,
        };

        let reader = match self.ty {
            ConversionType::EStargzToRef
            | ConversionType::TargzToRef
            | ConversionType::TarToRef => match Self::detect_compression_algo(file)? {
                (CompressionType::Gzip, buf_reader) => {
                    let generator = ZranContextGenerator::from_buf_reader(buf_reader)?;
                    let reader = generator.reader();
                    self.ctx.blob_zran_generator = Some(Mutex::new(generator));
                    self.ctx.blob_features.insert(BlobFeatures::ZRAN);
                    TarReader::ZranReader(reader)
                }
                (CompressionType::None, buf_reader) => {
                    self.ty = ConversionType::TarToRef;
                    let reader = BufReaderInfo::from_buf_reader(buf_reader);
                    self.ctx.blob_tar_reader = Some(reader.clone());
                    TarReader::BufReaderInfo(reader)
                }
            },
            ConversionType::EStargzToRafs
            | ConversionType::TargzToRafs
            | ConversionType::TarToRafs => match Self::detect_compression_algo(file)? {
                (CompressionType::Gzip, buf_reader) => {
                    if is_file {
                        let mut file = buf_reader.into_inner();
                        file.seek(SeekFrom::Start(0))?;
                        TarReader::TarGzFile(Box::new(ZlibDecoder::new(file)))
                    } else {
                        TarReader::TarGzBufReader(Box::new(ZlibDecoder::new(buf_reader)))
                    }
                }
                (CompressionType::None, buf_reader) => {
                    if is_file {
                        let mut file = buf_reader.into_inner();
                        file.seek(SeekFrom::Start(0))?;
                        TarReader::File(file)
                    } else {
                        TarReader::BufReader(buf_reader)
                    }
                }
            },
            ConversionType::TarToTarfs => {
                let mut reader = BufReaderInfo::from_buf_reader(BufReader::new(file));
                self.ctx.blob_tar_reader = Some(reader.clone());
                if !self.ctx.blob_id.is_empty() {
                    reader.enable_digest_calculation(false);
                } else {
                    // Disable seek when need to calculate hash value.
                    is_file = false;
                }
                // only enable seek when hash computing is disabled.
                if is_file {
                    TarReader::BufReaderInfoSeekable(reader)
                } else {
                    TarReader::BufReaderInfo(reader)
                }
            }
            _ => return Err(anyhow!("tarball: unsupported image conversion type")),
        };

        let is_seekable = reader.seekable();
        let mut members = Members::new(reader, is_seekable);

        // Prepare scratch buffer for dumping file data.
        if self.buf.len() < self.ctx.chunk_size as usize {
            self.buf = vec![0u8; self.ctx.chunk_size as usize];
        }

        // Generate the root node in advance, it may be overwritten by entries from the tar stream.
        let root = self.builder.create_directory(&[OsString::from("/")])?;
        let mut tree = Tree::new(root);

        // Generate RAFS node for each tar entry, and optionally adding missing parents.
        while let Some(member) = members
            .next_member()
            .context("tarball: failed to read entry from tar")?
        {
            let path = resolve_path(&tree, &clean_path(&member.path))
                .with_context(|| format!("tarball: entry {}", show(&member.path)))?;
            if member.header.entry_type().is_pax_global_extensions() {
                // Apply ignores a global header, after removing whatever its name held and
                // creating its parent directories.
                // shortcut: only a header named at the root and naming nothing is accepted,
                // which covers the `pax_global_header` of `git archive`.
                if path.parent() != Some(Path::new("/")) || tree.get_node(&path).is_some() {
                    bail!("tarball: unsupported pax global header {}", path.display());
                }
                continue;
            }
            // Apply ignores a member resolving to the root directory.
            if path != Path::new("/") && !self.builder.is_stargz_special_files(&path) {
                self.parse_entry(&mut tree, &member, &mut members.data(), &path)?;
            }
        }

        // Update directory size for RAFS V5 after generating the tree.
        if self.ctx.fs_version.is_v5() {
            Self::set_v5_dir_size(&mut tree);
        }

        Ok(tree)
    }

    fn parse_entry<R: Read>(
        &mut self,
        tree: &mut Tree,
        entry: &Member,
        data: &mut R,
        path: &Path,
    ) -> Result<()> {
        let header = &entry.header;
        let entry_type = header.entry_type();
        if entry_type.is_gnu_longname() {
            return Err(anyhow!("tarball: unsupported gnu_longname from tar header"));
        } else if entry_type.is_gnu_longlink() {
            return Err(anyhow!("tarball: unsupported gnu_longlink from tar header"));
        } else if entry_type.is_pax_local_extensions() {
            return Err(anyhow!(
                "tarball: unsupported pax_local_extensions from tar header"
            ));
        } else if entry_type.is_pax_global_extensions() {
            return Err(anyhow!(
                "tarball: unsupported pax_global_extensions from tar header"
            ));
        } else if entry_type.is_contiguous() {
            return Err(anyhow!(
                "tarball: unsupported contiguous entry type from tar header"
            ));
        } else if entry_type.is_gnu_sparse() {
            return Err(anyhow!(
                "tarball: unsupported gnu sparse file extension from tar header"
            ));
        }

        let mut file_size = entry.size;
        let name = Self::get_file_name(path)?;
        let mut mode = Self::get_mode(header)?;
        let (mut uid, mut gid) = Self::get_uid_gid(self.ctx, entry)?;
        let mut mtime = header.mtime().unwrap_or_default();
        let mut flags = match self.ctx.fs_version {
            RafsVersion::V5 => RafsInodeFlags::default(),
            RafsVersion::V6 => RafsInodeFlags::default(),
        };

        // Parse special files.
        //
        // POSIX ustar defines `devmajor` and `devminor` for character and block special files
        // only, so an implementation is free to leave them NUL for a fifo, and GNU tar does
        // exactly that in all of its `gnu`, `ustar` and `posix` formats. A v7 entry carries no
        // such fields at all. A fifo has no device number anyway: `stat()` reports `st_rdev` of
        // 0 for it, which is what the directory builder stores, so store the same here instead
        // of reading fields the entry is not required to carry.
        let mut rdev = if entry_type.is_block_special() || entry_type.is_character_special() {
            let major = header
                .device_major()
                .context("tarball: failed to get device major from tar entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get major device from tar entry"))?;
            let minor = header
                .device_minor()
                .context("tarball: failed to get device minor from tar entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get minor device from tar entry"))?;
            makedev(major as u64, minor as u64) as u32
        } else if entry_type.is_fifo() {
            0
        } else {
            u32::MAX
        };

        // Parse symlink
        let (mut symlink, mut symlink_size) = if entry_type.is_symlink() {
            if entry.link.is_empty() {
                bail!("tarball: failed to get symlink target for tar entry");
            }
            let symlink_link_path = OsStr::from_bytes(&entry.link);
            let symlink_size = symlink_link_path.byte_size();
            if symlink_size > u16::MAX as usize {
                bail!("tarball: symlink target from tar entry is too big");
            }
            file_size = symlink_size as u64;
            flags |= RafsInodeFlags::SYMLINK;
            (Some(symlink_link_path.to_owned()), symlink_size as u16)
        } else {
            (None, 0)
        };

        let mut child_count = 0;
        if entry_type.is_file() {
            child_count = div_round_up(file_size, self.ctx.chunk_size as u64);
            if child_count > RAFS_MAX_CHUNKS_PER_BLOB as u64 {
                bail!("tarball: file size 0x{:x} is too big", file_size);
            }
        }

        // Parse xattrs
        let mut xattrs = RafsXAttrs::new();
        for (key, value) in &entry.pax {
            if let Some(x_key) = key.strip_prefix(b"SCHILY.xattr.") {
                xattrs.add(OsStr::from_bytes(x_key).to_os_string(), value.clone())?;
            }
        }

        // Handle hardlink ino
        let mut hardlink_target = None;
        let ino = if entry_type.is_hard_link() {
            if entry.link.is_empty() {
                bail!("tarball: failed to get hardlink target for tar entry");
            }
            // Like containerd's `hardlinkRootPath`, the link name is resolved as it is, not
            // cleaned first, and its last component is not followed.
            let link_path = resolve_path(tree, &entry.link)
                .with_context(|| format!("tarball: hardlink target {}", show(&entry.link)))?;
            let link_path = link_path.as_path();
            let Some(tmp_tree) = tree.get_node(link_path) else {
                bail!(
                    "tarball: unknown target {} for hardlink {}",
                    link_path.display(),
                    path.display()
                );
            };
            let mut tmp_node = tmp_tree.borrow_mut_node();
            if tmp_node.is_reg() {
                hardlink_target = Some(tmp_tree);
                flags |= RafsInodeFlags::HARDLINK;
                tmp_node.inode.set_has_hardlink(true);
                // Both names are one inode, so both must report one set of
                // metadata -- see the note on extraction semantics below. Taking
                // it from the target matches what the xattr copy further down
                // already does; leaving the link's own header values here made
                // RAFS v5 emit two inodes sharing an ino but disagreeing on
                // mode/uid/gid/mtime (a state no kernel can produce), and RAFS
                // v6, where the two names share one on-disk inode region, decide
                // between them by dump order.
                mode = tmp_node.inode.mode();
                uid = tmp_node.inode.uid();
                gid = tmp_node.inode.gid();
                mtime = tmp_node.inode.mtime();
                tmp_node.inode.ino()
            } else if tmp_node.is_dir() {
                bail!(
                    "tarball: target {} for hardlink {} is a directory",
                    link_path.display(),
                    path.display()
                );
            } else {
                // RAFS only represents hardlinks for regular files, so a hardlink to a symlink
                // or to a special file becomes an independent node cloned from the target. Such
                // nodes carry all their information in the inode, so nothing gets duplicated in
                // the data blob.
                //
                // Metadata comes from the target, here and in the regular-file branch above.
                // A hardlink name is created with link(2) and resolves to the target's inode,
                // so the two names cannot carry different metadata however the archive spells
                // it -- what they must never do is disagree. Which side wins is a real choice:
                // GNU tar creates the link and applies nothing from its header, while
                // containerd's and moby's layer extractors fall through to chown/chmod/chtimes
                // afterwards and so let the LINK's header overwrite the target's. Producers
                // that archive a real filesystem (GNU tar, bsdtar, Go's tar.FileInfoHeader as
                // used by buildkit) lstat one inode for both names and emit identical headers,
                // so the two conventions only diverge on synthesized archives.
                mode = tmp_node.inode.mode();
                uid = tmp_node.inode.uid();
                gid = tmp_node.inode.gid();
                mtime = tmp_node.inode.mtime();
                rdev = tmp_node.inode.rdev();
                file_size = tmp_node.inode.size();
                symlink = tmp_node.info.symlink.clone();
                symlink_size = tmp_node.inode.symlink_size();
                xattrs = tmp_node.info.xattrs.clone();
                if tmp_node.is_symlink() {
                    flags |= RafsInodeFlags::SYMLINK;
                }
                self.builder.next_ino()
            }
        } else {
            self.builder.next_ino()
        };

        let mut inode = match self.ctx.fs_version {
            RafsVersion::V5 => InodeWrapper::V5(RafsV5Inode {
                i_digest: RafsDigest::default(),
                i_parent: 0,
                i_ino: ino,
                i_projid: 0,
                i_uid: uid,
                i_gid: gid,
                i_mode: mode,
                i_size: file_size,
                i_nlink: 1,
                i_blocks: 0,
                i_flags: flags,
                i_child_index: 0,
                i_child_count: child_count as u32,
                i_name_size: name.len() as u16,
                i_symlink_size: symlink_size,
                i_rdev: rdev,
                i_mtime: mtime,
                i_mtime_nsec: 0,
                i_reserved: [0; 8],
            }),
            RafsVersion::V6 => InodeWrapper::V6(RafsV6Inode {
                i_ino: ino,
                i_projid: 0,
                i_uid: uid,
                i_gid: gid,
                i_mode: mode,
                i_size: file_size,
                i_nlink: 1,
                i_blocks: 0,
                i_flags: flags,
                i_child_count: child_count as u32,
                i_name_size: name.len() as u16,
                i_symlink_size: symlink_size,
                i_rdev: rdev,
                i_mtime: mtime,
                i_mtime_nsec: 0,
            }),
        };
        inode.set_has_xattr(!xattrs.is_empty());

        let source = PathBuf::from("/");
        let target = Node::generate_target(path, &source);
        let target_vec = Node::generate_target_vec(&target);
        let info = NodeInfo {
            explicit_uidgid: self.ctx.explicit_uidgid,
            src_ino: ino,
            src_dev: u64::MAX,
            rdev: rdev as u64,
            path: path.to_path_buf(),
            source,
            target,
            target_vec,
            symlink,
            xattrs,
            v6_force_extended_inode: false,
        };
        let mut node = Node::new(inode, info, self.builder.layer_idx);

        // Special handling of hardlink.
        // Tar hardlink header has zero file size and no file data associated, so copy value from
        // the associated regular file.
        if let Some(t) = hardlink_target {
            let n = t.borrow_mut_node();
            if n.inode.is_v5() {
                node.inode.set_digest(n.inode.digest().to_owned());
            }
            node.inode.set_size(n.inode.size());
            node.inode.set_child_count(n.inode.child_count());
            node.chunks = n.chunks.clone();
            // All names of a hardlink share a single inode, and for RAFS v6 they literally share
            // its on-disk region, whose size was reserved from the target. The xattrs must
            // therefore stay identical to the target's, even if the hardlink entry recorded
            // xattrs of its own.
            node.set_xattr(n.info.xattrs.clone());
        } else {
            node.dump_node_data_with_reader(
                self.ctx,
                self.blob_mgr,
                self.blob_writer,
                Some(data),
                &mut self.buf,
            )?;
        }

        // Update inode.i_blocks for RAFS v5.
        if self.ctx.fs_version == RafsVersion::V5 && !entry_type.is_dir() {
            node.v5_set_inode_blocks();
        }

        self.builder.insert_into_tree(tree, node)
    }

    fn get_uid_gid(ctx: &BuildContext, entry: &Member) -> Result<(u32, u32)> {
        let (uid, gid) = if ctx.explicit_uidgid {
            (entry.uid, entry.gid)
        } else {
            (0, 0)
        };
        if uid > u32::MAX as u64 || gid > u32::MAX as u64 {
            bail!(
                "tarball: uid {:x} or gid {:x} from tar entry is out of range",
                uid,
                gid
            );
        }

        Ok((uid as u32, gid as u32))
    }

    fn get_mode(header: &Header) -> Result<u32> {
        let mode = header
            .mode()
            .context("tarball: failed to get permission/mode from tar entry")?;
        let ty = match header.entry_type() {
            EntryType::Regular | EntryType::Link => crate::mode_bits(libc::S_IFREG),
            EntryType::Directory => crate::mode_bits(libc::S_IFDIR),
            EntryType::Symlink => crate::mode_bits(libc::S_IFLNK),
            EntryType::Block => crate::mode_bits(libc::S_IFBLK),
            EntryType::Char => crate::mode_bits(libc::S_IFCHR),
            EntryType::Fifo => crate::mode_bits(libc::S_IFIFO),
            _ => bail!("tarball: unsupported tar entry type"),
        };
        Ok((mode & !crate::mode_bits(libc::S_IFMT)) | ty)
    }

    fn get_file_name(path: &Path) -> Result<&OsStr> {
        let name = if path == Path::new("/") {
            path.as_os_str()
        } else {
            path.file_name().ok_or_else(|| {
                anyhow!(
                    "tarball: failed to get file name from tar entry with path {}",
                    path.display()
                )
            })?
        };
        if name.len() > u16::MAX as usize {
            bail!(
                "tarball: file name {} from tar entry is too long",
                name.to_str().unwrap_or_default()
            );
        }
        Ok(name)
    }

    fn set_v5_dir_size(tree: &mut Tree) {
        for c in &mut tree.children {
            Self::set_v5_dir_size(c);
        }
        let mut node = tree.borrow_mut_node();
        node.v5_set_dir_size(RafsVersion::V5, &tree.children);
    }

    fn detect_compression_algo(file: File) -> Result<(CompressionType, BufReader<File>)> {
        // Use 64K buffer to keep consistence with zlib-random.
        let mut buf_reader = BufReader::with_capacity(ZRAN_READER_BUF_SIZE, file);
        let mut buf = [0u8; 3];
        buf_reader.read_exact(&mut buf)?;
        if buf[0] == 0x1f && buf[1] == 0x8b && buf[2] == 0x08 {
            buf_reader.seek_relative(-3).unwrap();
            Ok((CompressionType::Gzip, buf_reader))
        } else {
            buf_reader.seek_relative(-3).unwrap();
            Ok((CompressionType::None, buf_reader))
        }
    }
}

/// Most symlinks followed while resolving one member name, as in continuity's `fs.RootPath`.
const MAX_SYMLINKS: usize = 255;

fn show(p: &[u8]) -> String {
    String::from_utf8_lossy(p).into_owned()
}

/// Cleans a member name lexically, as containerd's `filepath.Clean` does before resolving it:
/// `.` and empty components go, and `..` removes the component before it, never the root.
fn clean_path(name: &[u8]) -> Vec<u8> {
    let mut out: Vec<&[u8]> = Vec::new();
    for c in name.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out.join(&b'/')
}

/// Resolves a member name to the absolute path containerd's `archive.Apply` lands it on:
/// relative to the root of the layer, `..` stops at the root, and each leading component that
/// is a symlink from an earlier member is followed within the root, while the last component
/// is not. Only symlinks of this layer are known, the layers below it are not.
fn resolve_path(tree: &Tree, name: &[u8]) -> Result<PathBuf> {
    let mut pending: VecDeque<Vec<u8>> = name.split(|&b| b == b'/').map(<[u8]>::to_vec).collect();
    // `trees[i]` is the tree at `resolved[..i]`, `None` once a component does not exist.
    let mut resolved: Vec<Vec<u8>> = Vec::new();
    let mut trees: Vec<Option<&Tree>> = vec![Some(tree)];
    let mut followed = 0;
    while let Some(c) = pending.pop_front() {
        match c.as_slice() {
            b"" | b"." => continue,
            b".." => {
                if resolved.pop().is_some() {
                    trees.pop();
                }
                continue;
            }
            _ => {}
        }
        let child =
            trees[trees.len() - 1].and_then(|t| t.get_child_idx(&c).map(|i| &t.children[i]));
        resolved.push(c);
        trees.push(child);
        if pending.is_empty() {
            break;
        }
        let Some(child) = child else { continue };
        let node = child.borrow_mut_node();
        if node.is_dir() {
            continue;
        }
        let Some(target) = node.info.symlink.clone().filter(|_| node.is_symlink()) else {
            bail!("{} is not a directory", show(&resolved.join(&b'/')));
        };
        followed += 1;
        if followed > MAX_SYMLINKS {
            bail!("too many levels of symbolic links");
        }
        resolved.pop();
        trees.pop();
        if target.as_bytes().starts_with(b"/") {
            resolved.clear();
            trees.truncate(1);
        }
        for c in target.as_bytes().split(|&b| b == b'/').rev() {
            pending.push_front(c.to_vec());
        }
    }
    let mut path = PathBuf::from("/");
    for c in &resolved {
        path.push(OsStr::from_bytes(c));
    }
    Ok(path)
}

/// Builder to create RAFS filesystems from tarballs.
///
/// Note that hardlinks are only preserved for regular files, since RAFS represents hardlinks by
/// sharing an inode between regular files. A tar hardlink entry whose target is a symlink or a
/// special file becomes an independent node with the metadata of its target, so the generated
/// filesystem reports `nlink` of 1 for both names instead of 2.
pub struct TarballBuilder {
    ty: ConversionType,
}

impl TarballBuilder {
    /// Create a new instance of [TarballBuilder] to build a RAFS filesystem from a tarball.
    pub fn new(conversion_type: ConversionType) -> Self {
        Self {
            ty: conversion_type,
        }
    }
}

impl Builder for TarballBuilder {
    fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput> {
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx(ctx.v6_block_size())?;
        let layer_idx = u16::from(bootstrap_ctx.layered);
        let mut blob_writer: Box<dyn Artifact> = match self.ty {
            ConversionType::EStargzToRafs
            | ConversionType::EStargzToRef
            | ConversionType::TargzToRafs
            | ConversionType::TargzToRef
            | ConversionType::TarToRafs
            | ConversionType::TarToTarfs => {
                if let Some(blob_stor) = ctx.blob_storage.clone() {
                    Box::new(ArtifactWriter::new(blob_stor)?)
                } else {
                    Box::<NoopArtifactWriter>::default()
                }
            }
            _ => {
                return Err(anyhow!(
                    "tarball: unsupported image conversion type '{}'",
                    self.ty
                ));
            }
        };

        let mut tree_builder =
            TarballTreeBuilder::new(self.ty, ctx, blob_mgr, blob_writer.as_mut(), layer_idx);
        let tree = timing_tracer!({ tree_builder.build_tree() }, "build_tree")?;

        // Build bootstrap
        let mut bootstrap = timing_tracer!(
            { build_bootstrap(ctx, bootstrap_mgr, &mut bootstrap_ctx, blob_mgr, tree) },
            "build_bootstrap"
        )?;

        // Dump blob file
        timing_tracer!(
            { Blob::dump(ctx, blob_mgr, blob_writer.as_mut()) },
            "dump_blob"
        )?;

        // Dump blob meta information
        if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
            Blob::dump_meta_data(ctx, blob_ctx, blob_writer.as_mut())?;
        }

        // Dump RAFS meta/bootstrap and finalize the data blob.
        if ctx.blob_inline_meta {
            timing_tracer!(
                {
                    dump_bootstrap(
                        ctx,
                        bootstrap_mgr,
                        &mut bootstrap_ctx,
                        &mut bootstrap,
                        blob_mgr,
                        blob_writer.as_mut(),
                    )
                },
                "dump_bootstrap"
            )?;
            finalize_blob(ctx, blob_mgr, blob_writer.as_mut())?;
        } else {
            finalize_blob(ctx, blob_mgr, blob_writer.as_mut())?;
            timing_tracer!(
                {
                    dump_bootstrap(
                        ctx,
                        bootstrap_mgr,
                        &mut bootstrap_ctx,
                        &mut bootstrap,
                        blob_mgr,
                        blob_writer.as_mut(),
                    )
                },
                "dump_bootstrap"
            )?;
        }

        lazy_drop(bootstrap_ctx);

        BuildOutput::new(blob_mgr, None, &bootstrap_mgr.bootstrap_storage, &None)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::attributes::Attributes;
    use crate::{ArtifactStorage, Bootstrap, BootstrapContext, Features, Prefetch, WhiteoutSpec};
    use nydus_rafs::metadata::layout::v6::EROFS_BLOCK_SIZE_4096;
    use nydus_utils::{compress, digest};

    // Metadata of the hardlink targets in `create_hardlink_tar`, chosen to differ from the
    // metadata of the hardlink entries pointing at them.
    const TARGET_MODE: u32 = 0o755;
    const TARGET_UID: u64 = 7;
    const TARGET_GID: u64 = 8;
    const TARGET_MTIME: u64 = 111;

    #[allow(clippy::too_many_arguments)]
    fn append_entry_with_meta(
        tar: &mut tar::Builder<File>,
        path: &str,
        entry_type: EntryType,
        link_name: Option<&str>,
        data: &[u8],
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
    ) {
        let mut header = Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_mode(mode);
        header.set_uid(uid);
        header.set_gid(gid);
        header.set_mtime(mtime);
        header.set_size(data.len() as u64);
        if let Some(link_name) = link_name {
            header.set_link_name(link_name).unwrap();
        }
        if entry_type == EntryType::Fifo {
            header.set_device_major(0).unwrap();
            header.set_device_minor(0).unwrap();
        }
        tar.append_data(&mut header, path, data).unwrap();
    }

    fn append_entry(
        tar: &mut tar::Builder<File>,
        path: &str,
        entry_type: EntryType,
        link_name: Option<&str>,
        data: &[u8],
    ) {
        append_entry_with_meta(tar, path, entry_type, link_name, data, 0o644, 0, 0, 0);
    }

    // Generate a tar stream containing hardlinks to a symlink, to a fifo and to a regular file.
    // The hardlinks to the symlink live in a subdirectory, so that the node created for them gets
    // an inode number greater than the inode number of its parent directory. The targets carry
    // metadata which differs from their hardlink entries, so that a node built from the target is
    // distinguishable from one built from the hardlink header.
    fn create_hardlink_tar(path: &Path) {
        let mut tar = tar::Builder::new(File::create(path).unwrap());
        // The regular target carries the same distinguishing metadata as the
        // sym/fifo targets, so a node built from the target is distinguishable
        // from one built from the link entry's own (default) header.
        append_entry_with_meta(
            &mut tar,
            "foo",
            EntryType::Regular,
            None,
            b"hello",
            TARGET_MODE,
            TARGET_UID,
            TARGET_GID,
            TARGET_MTIME,
        );
        for (name, entry_type) in [("sym", EntryType::Symlink), ("fifo", EntryType::Fifo)] {
            let link_name = (entry_type == EntryType::Symlink).then_some("foo");
            append_entry_with_meta(
                &mut tar,
                name,
                entry_type,
                link_name,
                b"",
                TARGET_MODE,
                TARGET_UID,
                TARGET_GID,
                TARGET_MTIME,
            );
        }
        append_entry(&mut tar, "dir/", EntryType::Directory, None, b"");
        append_entry(
            &mut tar,
            "dir/sym-link",
            EntryType::Link,
            Some("./sym"),
            b"",
        );
        append_entry(
            &mut tar,
            "dir/fifo-link",
            EntryType::Link,
            Some("fifo"),
            b"",
        );
        append_entry(&mut tar, "dir/foo-link", EntryType::Link, Some("foo"), b"");
        tar.finish().unwrap();
    }

    fn create_context(source_path: PathBuf, version: RafsVersion) -> BuildContext {
        let mut ctx = BuildContext::new(
            "test".to_string(),
            true,
            0,
            compress::Algorithm::None,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::Oci,
            ConversionType::TarToRafs,
            source_path,
            Prefetch::default(),
            None,
            None,
            false,
            Features::new(),
            false,
            Attributes::default(),
        );
        ctx.fs_version = version;
        ctx
    }

    fn build_tree(ctx: &mut BuildContext) -> Result<Tree> {
        build_tree_as(ctx, ConversionType::TarToRafs)
    }

    fn build_tree_as(ctx: &mut BuildContext, ty: ConversionType) -> Result<Tree> {
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        let mut blob_writer: Box<dyn Artifact> = Box::<NoopArtifactWriter>::default();
        let mut tree_builder =
            TarballTreeBuilder::new(ty, ctx, &mut blob_mgr, blob_writer.as_mut(), 0);
        tree_builder.build_tree()
    }

    fn build_rafs(ctx: &mut BuildContext) -> Bootstrap {
        let tree = build_tree(ctx).unwrap();
        let mut bootstrap_ctx = BootstrapContext::new(None, false, EROFS_BLOCK_SIZE_4096).unwrap();
        let mut bootstrap = Bootstrap::new(tree).unwrap();
        bootstrap.build(ctx, &mut bootstrap_ctx).unwrap();
        bootstrap
    }

    fn get_node(bootstrap: &Bootstrap, path: &str) -> Node {
        bootstrap
            .tree
            .get_node(Path::new(path))
            .unwrap()
            .borrow_mut_node()
            .clone()
    }

    // The metadata of an independent node created for a hardlink entry must come from the target
    // node, since extracting the entry would create a name resolving to the inode of the target.
    fn assert_metadata_from_target(node: &Node, target: &Node, file_type: libc::mode_t) {
        assert_eq!(node.inode.mode(), target.inode.mode());
        assert_eq!(node.inode.mode(), crate::mode_bits(file_type) | TARGET_MODE);
        assert_eq!(node.inode.uid(), TARGET_UID as u32);
        assert_eq!(node.inode.gid(), TARGET_GID as u32);
        assert_eq!(node.inode.mtime(), TARGET_MTIME);
        assert_eq!(node.info.xattrs.is_empty(), target.info.xattrs.is_empty());
    }

    fn test_hardlink_to_non_regular_file(version: RafsVersion) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let tmp_dir = tmp_dir.as_path().to_path_buf();
        let source_path = tmp_dir.join("hardlink.tar");
        create_hardlink_tar(&source_path);
        let mut ctx = create_context(source_path.clone(), version);
        let bootstrap = build_rafs(&mut ctx);

        // A hardlink to a symlink becomes an independent symlink node with the same target,
        // instead of sharing the inode of the target as a hardlink to a regular file does. Its
        // metadata comes from the target, not from the header of the hardlink entry.
        let sym = get_node(&bootstrap, "/sym");
        let sym_link = get_node(&bootstrap, "/dir/sym-link");
        assert!(sym_link.is_symlink());
        assert_eq!(sym_link.info.symlink, Some(OsString::from("foo")));
        assert_eq!(sym_link.inode.symlink_size(), 3);
        assert_eq!(sym_link.inode.size(), 3);
        assert_ne!(sym_link.inode.ino(), sym.inode.ino());
        assert_eq!(sym_link.inode.nlink(), 1);
        // A hardlink entry has no file data, so it never gets chunks.
        assert_eq!(sym_link.inode.child_count(), 0);
        assert_metadata_from_target(&sym_link, &sym, libc::S_IFLNK);
        if version.is_v5() {
            // The digest of a v5 symlink is computed from its target, so an independent node
            // must have gone through the regular symlink dump path.
            assert_eq!(sym_link.inode.digest(), sym.inode.digest());
        }

        // Same for a hardlink to a special file, which also keeps the device number.
        let fifo = get_node(&bootstrap, "/fifo");
        let fifo_link = get_node(&bootstrap, "/dir/fifo-link");
        assert!(fifo_link.is_special());
        assert_eq!(fifo_link.inode.rdev(), fifo.inode.rdev());
        assert_ne!(fifo_link.inode.ino(), fifo.inode.ino());
        assert_eq!(fifo_link.inode.nlink(), 1);
        assert_eq!(fifo_link.inode.child_count(), 0);
        assert_metadata_from_target(&fifo_link, &fifo, libc::S_IFIFO);

        // A hardlink to a regular file is still coalesced into a single inode.
        let foo = get_node(&bootstrap, "/foo");
        let foo_link = get_node(&bootstrap, "/dir/foo-link");
        assert!(foo_link.is_hardlink());
        assert_eq!(foo_link.inode.ino(), foo.inode.ino());
        assert_eq!(foo_link.inode.nlink(), 2);
        assert_eq!(foo.inode.nlink(), 2);
        assert_eq!(foo_link.inode.size(), 5);
        assert_eq!(foo_link.inode.child_count(), 1);
        assert_eq!(foo_link.chunks.len(), 1);
        // ...and both names must report ONE set of metadata. `foo-link`'s own
        // header carries the append_entry defaults (0o644, uid/gid/mtime 0),
        // which differ from the target's, so this fails if the link keeps them:
        // v5 would emit two inodes sharing an ino but disagreeing, and v6, where
        // both names share one on-disk inode region, would resolve the conflict
        // by dump order.
        assert_metadata_from_target(&foo_link, &foo, libc::S_IFREG);

        // The same tarball must also convert end to end, including blob and bootstrap dump.
        let mut ctx = create_context(source_path, version);
        ctx.blob_storage = Some(ArtifactStorage::FileDir((tmp_dir.clone(), String::new())));
        let mut bootstrap_mgr = BootstrapManager::new(
            Some(ArtifactStorage::FileDir((tmp_dir, String::new()))),
            None,
        );
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        TarballBuilder::new(ConversionType::TarToRafs)
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
    }

    #[test]
    fn test_v5_hardlink_to_non_regular_file() {
        test_hardlink_to_non_regular_file(RafsVersion::V5);
    }

    #[test]
    fn test_v6_hardlink_to_non_regular_file() {
        test_hardlink_to_non_regular_file(RafsVersion::V6);
    }

    // Append an entry whose `devmajor`/`devminor` fields are left NUL, the way Go's
    // `archive/tar` writes every entry which is not a character or block special file.
    fn append_entry_without_device_numbers(
        tar: &mut tar::Builder<File>,
        path: &str,
        entry_type: EntryType,
    ) {
        let mut header = Header::new_ustar();
        header.set_entry_type(entry_type);
        header.set_mode(0o700);
        header.set_size(0);
        header.set_path(path).unwrap();
        // `devmajor` and `devminor` occupy bytes 329..345 of a ustar header.
        header.as_mut_bytes()[329..345].fill(0);
        header.set_cksum();
        tar.append(&header, &[][..]).unwrap();
    }

    fn test_fifo_without_device_numbers(version: RafsVersion) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("fifo.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        append_entry_without_device_numbers(&mut tar, "fifo-entry", EntryType::Fifo);
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, version);
        let bootstrap = build_rafs(&mut ctx);

        let fifo = get_node(&bootstrap, "/fifo-entry");
        assert!(fifo.is_special());
        // A fifo has no device number, and `stat()` reports `st_rdev` of 0 for it, so a fifo
        // built from a directory carries 0. One built from a tarball must match.
        assert_eq!(fifo.inode.rdev(), 0);
        assert_eq!(fifo.info.rdev, 0);
    }

    #[test]
    fn test_v5_fifo_without_device_numbers() {
        test_fifo_without_device_numbers(RafsVersion::V5);
    }

    #[test]
    fn test_v6_fifo_without_device_numbers() {
        test_fifo_without_device_numbers(RafsVersion::V6);
    }

    // Character and block special files are the two types POSIX defines `devmajor`/`devminor`
    // for, so they must keep round-tripping their device number.
    fn test_device_files_keep_rdev(version: RafsVersion) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("devices.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        for (name, entry_type) in [("chr", EntryType::Char), ("blk", EntryType::Block)] {
            let mut header = Header::new_ustar();
            header.set_entry_type(entry_type);
            header.set_mode(0o600);
            header.set_size(0);
            header.set_device_major(136).unwrap();
            header.set_device_minor(3).unwrap();
            tar.append_data(&mut header, name, &[][..]).unwrap();
        }
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, version);
        let bootstrap = build_rafs(&mut ctx);

        let expected = makedev(136, 3) as u32;
        for name in ["/chr", "/blk"] {
            let node = get_node(&bootstrap, name);
            assert!(node.is_special());
            assert_eq!(node.inode.rdev(), expected);
        }
    }

    #[test]
    fn test_v5_device_files_keep_rdev() {
        test_device_files_keep_rdev(RafsVersion::V5);
    }

    #[test]
    fn test_v6_device_files_keep_rdev() {
        test_device_files_keep_rdev(RafsVersion::V6);
    }

    #[test]
    fn test_hardlink_to_directory_is_rejected() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("hardlink-dir.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        append_entry(&mut tar, "dir/", EntryType::Directory, None, b"");
        append_entry(&mut tar, "dir-link", EntryType::Link, Some("dir"), b"");
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let err = build_tree(&mut ctx).err().unwrap();
        assert!(err.to_string().contains("is a directory"), "{}", err);
    }

    #[test]
    fn test_hardlink_to_unknown_target_is_rejected() {
        // A tar entry may only be hardlinked to an entry which appeared earlier in the stream,
        // because the tarball is parsed in a single pass.
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("hardlink-unknown.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        append_entry(&mut tar, "sym-link", EntryType::Link, Some("sym"), b"");
        append_entry(&mut tar, "sym", EntryType::Symlink, Some("foo"), b"");
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let err = build_tree(&mut ctx).err().unwrap();
        assert!(err.to_string().contains("unknown target"), "{}", err);
    }

    #[test]
    fn test_malformed_pax_extension_is_rejected() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("bad-pax.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        // A PAX record starts with its own length in decimal, here reported too long.
        let pax = "99 SCHILY.xattr.user.key=value\n";
        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::XHeader);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_size(pax.len() as u64);
        tar.append_data(&mut header, "PaxHeaders/foo", pax.as_bytes())
            .unwrap();
        append_entry(&mut tar, "foo", EntryType::Regular, None, b"hello");
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let err = format!("{:#}", build_tree(&mut ctx).err().unwrap());
        assert!(err.contains("bad PAX record"), "{}", err);
    }

    #[test]
    fn test_build_tarfs() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let tmp_dir = tmp_dir.as_path().to_path_buf();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let source_path = PathBuf::from(root_dir).join("../tests/texture/tar/all-entry-type.tar");
        let prefetch = Prefetch::default();
        let mut ctx = BuildContext::new(
            "test".to_string(),
            true,
            0,
            compress::Algorithm::None,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::Oci,
            ConversionType::TarToTarfs,
            source_path,
            prefetch,
            Some(ArtifactStorage::FileDir((tmp_dir.clone(), String::new()))),
            None,
            false,
            Features::new(),
            false,
            Attributes::default(),
        );
        let mut bootstrap_mgr = BootstrapManager::new(
            Some(ArtifactStorage::FileDir((tmp_dir, String::new()))),
            None,
        );
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        let mut builder = TarballBuilder::new(ConversionType::TarToTarfs);
        builder
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
    }

    #[test]
    fn test_build_encrypted_tarfs() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let tmp_dir = tmp_dir.as_path().to_path_buf();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let source_path = PathBuf::from(root_dir).join("../tests/texture/tar/all-entry-type.tar");
        let prefetch = Prefetch::default();
        let mut ctx = BuildContext::new(
            "test".to_string(),
            true,
            0,
            compress::Algorithm::None,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::Oci,
            ConversionType::TarToTarfs,
            source_path,
            prefetch,
            Some(ArtifactStorage::FileDir((tmp_dir.clone(), String::new()))),
            None,
            false,
            Features::new(),
            true,
            Attributes::default(),
        );
        let mut bootstrap_mgr = BootstrapManager::new(
            Some(ArtifactStorage::FileDir((tmp_dir, String::new()))),
            None,
        );
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        let mut builder = TarballBuilder::new(ConversionType::TarToTarfs);
        builder
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
    }

    // Build a tar holding a regular file, a hardlink to it and two more entries stored after the
    // hardlink, so that an inode written at a wrong offset is observable. `xattr_on` selects
    // which of the two names records an xattr in its own PAX header.
    fn create_xattr_hardlink_tar(path: &Path, xattr_on: &str) {
        let mut tar = tar::Builder::new(File::create(path).unwrap());
        let mut append = |name: &str, entry_type: EntryType, data: &[u8]| {
            if name == xattr_on {
                // A PAX extended header record is "<len> <key>=<value>\n", where <len> counts
                // the whole record including itself.
                let body = format!(" SCHILY.xattr.user.key={}\n", "v".repeat(600));
                let mut len = body.len() + 1;
                let pax = loop {
                    let pax = format!("{}{}", len, body);
                    if pax.len() == len {
                        break pax;
                    }
                    len = pax.len();
                };
                let mut header = Header::new_ustar();
                header.set_entry_type(EntryType::XHeader);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_size(pax.len() as u64);
                tar.append_data(&mut header, "PaxHeaders/entry", pax.as_bytes())
                    .unwrap();
            }
            let mut header = Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_size(data.len() as u64);
            if entry_type == EntryType::Link {
                header.set_link_name("foo").unwrap();
            }
            tar.append_data(&mut header, name, data).unwrap();
        };
        append("foo", EntryType::Regular, b"hello");
        append("foo-link", EntryType::Link, b"");
        append("zzz1", EntryType::Regular, b"world");
        append("zzz2", EntryType::Regular, b"world");
        tar.finish().unwrap();
    }

    fn build_and_load_xattr_hardlink_tar(
        version: RafsVersion,
        xattr_on: &str,
    ) -> nydus_rafs::metadata::RafsSuper {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let tmp_dir = tmp_dir.as_path().to_path_buf();
        let source_path = tmp_dir.join("xattr-hardlink.tar");
        let bootstrap_path = tmp_dir.join("bootstrap");
        create_xattr_hardlink_tar(&source_path, xattr_on);

        let mut ctx = BuildContext::new(
            "test".to_string(),
            true,
            0,
            compress::Algorithm::None,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::Oci,
            ConversionType::TarToRafs,
            source_path,
            Prefetch::default(),
            Some(ArtifactStorage::FileDir((tmp_dir, String::new()))),
            None,
            false,
            Features::new(),
            false,
            Attributes::default(),
        );
        ctx.fs_version = version;
        let mut bootstrap_mgr = BootstrapManager::new(
            Some(ArtifactStorage::SingleFile(bootstrap_path.clone())),
            None,
        );
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        TarballBuilder::new(ConversionType::TarToRafs)
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();

        // Loading the bootstrap back is what detects an inode written at a wrong offset.
        nydus_rafs::metadata::RafsSuper::load_from_file(
            &bootstrap_path,
            Arc::new(nydus_api::ConfigV2::default()),
            false,
        )
        .unwrap()
        .0
    }

    fn xattr_count(sb: &nydus_rafs::metadata::RafsSuper, name: &str) -> usize {
        let root = sb.get_inode(sb.superblock.root_ino(), false).unwrap();
        let child = root.get_child_by_name(OsStr::new(name)).unwrap();
        let inode = sb.get_inode(child.ino(), false).unwrap();
        inode.get_xattrs().unwrap().len()
    }

    // A hardlink entry inherits the xattrs of its target, which must be reflected in the inode
    // flags: the RAFS v5 inode table reserves room for the xattr table based on the flag, while
    // the xattr table itself is written whenever the node has xattrs. If the two disagree, every
    // inode after the hardlink is written at the wrong offset and the bootstrap can't be loaded.
    #[test]
    fn test_v5_hardlink_inherits_xattr_flag_from_target() {
        let sb = build_and_load_xattr_hardlink_tar(RafsVersion::V5, "foo");
        // Both names of the hardlink resolve to the inode of the target, which carries the xattr.
        assert_eq!(xattr_count(&sb, "foo"), 1);
        assert_eq!(xattr_count(&sb, "foo-link"), 1);
        // The entries stored after the hardlink must still be readable.
        assert_eq!(xattr_count(&sb, "zzz1"), 0);
        assert_eq!(xattr_count(&sb, "zzz2"), 0);
    }

    // All names of a hardlink share one inode, and for RAFS v6 they share its on-disk region,
    // whose size is reserved from the target. A hardlink entry keeping xattrs of its own would
    // write past that region, leaking them onto the target and corrupting the inodes stored after
    // it, so the xattrs of the target win even when only the hardlink entry recorded any.
    #[test]
    fn test_v6_hardlink_xattrs_stay_identical_to_target() {
        let sb = build_and_load_xattr_hardlink_tar(RafsVersion::V6, "foo-link");
        assert_eq!(xattr_count(&sb, "foo"), 0);
        assert_eq!(xattr_count(&sb, "foo-link"), 0);
        assert_eq!(xattr_count(&sb, "zzz1"), 0);
        assert_eq!(xattr_count(&sb, "zzz2"), 0);
    }

    // Layer tars below are written byte by byte, because the `tar` crate's writer refuses
    // most of the member names and records that containerd's `archive.Apply` has to cope with.
    const REG: u8 = b'0';
    const LINK: u8 = b'1';
    const SYMLINK: u8 = b'2';
    const DIR: u8 = b'5';

    fn octal(field: &mut [u8], value: u64) {
        let s = format!("{:0width$o}\0", value, width = field.len() - 1);
        field.copy_from_slice(s.as_bytes());
    }

    fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
        // "<len> <key>=<value>\n", where <len> counts the whole record including itself.
        let body = [b" ", key.as_bytes(), b"=", value, b"\n"].concat();
        let mut len = body.len() + 1;
        while (len.to_string().len() + body.len()) != len {
            len = len.to_string().len() + body.len();
        }
        [len.to_string().as_bytes(), &body].concat()
    }

    #[derive(Default)]
    struct RawTar(Vec<u8>);

    impl RawTar {
        fn member(self, typeflag: u8, name: &[u8], link: &[u8], mode: u64, data: &[u8]) -> Self {
            self.member_with(typeflag, name, link, mode, data, |_| {})
        }
        /// `tweak` edits the header block before its checksum is computed.
        fn member_with(
            mut self,
            typeflag: u8,
            name: &[u8],
            link: &[u8],
            mode: u64,
            data: &[u8],
            tweak: impl FnOnce(&mut [u8; 512]),
        ) -> Self {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name);
            octal(&mut h[100..108], mode);
            octal(&mut h[108..116], 0);
            octal(&mut h[116..124], 0);
            octal(&mut h[124..136], data.len() as u64);
            octal(&mut h[136..148], 0);
            h[156] = typeflag;
            h[157..157 + link.len()].copy_from_slice(link);
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            octal(&mut h[329..337], 0);
            octal(&mut h[337..345], 0);
            tweak(&mut h);
            h[148..156].fill(b' ');
            let sum: u64 = h.iter().map(|&b| b as u64).sum();
            h[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
            self.0.extend_from_slice(&h);
            self.0.extend_from_slice(data);
            self.0.resize(self.0.len().div_ceil(512) * 512, 0);
            self
        }
        fn reg(self, name: &str, data: &[u8]) -> Self {
            self.member(REG, name.as_bytes(), b"", 0o644, data)
        }
        fn dir(self, name: &str) -> Self {
            self.member(DIR, name.as_bytes(), b"", 0o755, b"")
        }
        fn sym(self, name: &str, target: &str) -> Self {
            self.member(SYMLINK, name.as_bytes(), target.as_bytes(), 0o777, b"")
        }
        fn link(self, name: &str, target: &str) -> Self {
            self.member(LINK, name.as_bytes(), target.as_bytes(), 0o644, b"")
        }
        fn pax(self, typeflag: u8, records: &[(&str, &[u8])]) -> Self {
            let body: Vec<u8> = records.iter().flat_map(|(k, v)| pax_record(k, v)).collect();
            self.member(typeflag, b"PaxHeaders/member", b"", 0o644, &body)
        }
        fn finish(mut self) -> Vec<u8> {
            self.0.extend_from_slice(&[0u8; 1024]);
            self.0
        }
    }

    fn layer_ctx(tar: &[u8]) -> (vmm_sys_util::tempdir::TempDir, BuildContext) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("layer.tar");
        std::fs::write(&source_path, tar).unwrap();
        let ctx = create_context(source_path, RafsVersion::V6);
        (tmp_dir, ctx)
    }

    fn build_layer(tar: &[u8]) -> Bootstrap {
        let (_tmp, mut ctx) = layer_ctx(tar);
        build_rafs(&mut ctx)
    }

    fn build_layer_err(tar: &[u8]) -> String {
        let (_tmp, mut ctx) = layer_ctx(tar);
        format!(
            "{:#}",
            build_tree(&mut ctx).err().expect("layer must be rejected")
        )
    }

    // Every path in the tree with its file type, in DFS order.
    fn outline(bootstrap: &Bootstrap) -> Vec<String> {
        let mut out = Vec::new();
        bootstrap
            .tree
            .walk_dfs_pre(&mut |t| {
                let node = t.borrow_mut_node();
                out.push(format!("{} {}", node.target().display(), node.file_type()));
                Ok(())
            })
            .unwrap();
        out
    }

    // The USTAR `prefix` field as Go's archive/tar reads it, since containerd and the
    // scanners see that name: a header that lands a file elsewhere here is a different image.
    fn prefixed_member(tweak: impl FnOnce(&mut [u8; 512])) -> Vec<u8> {
        RawTar::default()
            .member_with(REG, b"etc/ld.so.preload", b"", 0o644, b"x", |h| {
                h[345..360].copy_from_slice(b"usr/share/doc/x");
                tweak(h);
            })
            .finish()
    }

    #[test]
    fn test_ustar_prefix_applies_to_any_ustar_version() {
        let tar = prefixed_member(|h| h[263..265].copy_from_slice(b"  "));
        let bootstrap = build_layer(&tar);
        assert_eq!(
            get_node(&bootstrap, "/usr/share/doc/x/etc/ld.so.preload")
                .inode
                .size(),
            1
        );
        assert!(bootstrap.tree.get_node(Path::new("/etc")).is_none());
    }

    #[test]
    fn test_ustar_prefix_applies_with_version_00() {
        let bootstrap = build_layer(&prefixed_member(|_| {}));
        assert!(get_node(&bootstrap, "/usr/share/doc/x/etc/ld.so.preload").is_reg());
        assert!(bootstrap.tree.get_node(Path::new("/etc")).is_none());
    }

    #[test]
    fn test_star_trailer_shortens_the_prefix_to_131_bytes() {
        let tar = RawTar::default()
            .member_with(REG, b"f", b"", 0o644, b"x", |h| {
                h[345..476].fill(b'a');
                h[476..500].fill(b'b');
                h[508..512].copy_from_slice(b"tar\0");
            })
            .finish();
        let bootstrap = build_layer(&tar);
        let dir = "a".repeat(131);
        assert!(get_node(&bootstrap, &format!("/{dir}/f")).is_reg());
    }

    #[test]
    fn test_gnu_header_with_unparsable_atime_falls_back_to_the_prefix() {
        // The prefix field overlays GNU atime/ctime; a prefix that is not a number is
        // how a pre-Go1.8 writer's output looks, and Go reads it as the prefix.
        let tar = prefixed_member(|h| h[257..265].copy_from_slice(b"ustar  \0"));
        let bootstrap = build_layer(&tar);
        assert!(get_node(&bootstrap, "/usr/share/doc/x/etc/ld.so.preload").is_reg());
        assert!(bootstrap.tree.get_node(Path::new("/etc")).is_none());
    }

    #[test]
    fn test_gnu_header_with_valid_atime_has_no_prefix() {
        let tar = RawTar::default()
            .member_with(REG, b"etc/ld.so.preload", b"", 0o644, b"x", |h| {
                h[257..265].copy_from_slice(b"ustar  \0");
                octal(&mut h[345..357], 1_700_000_000);
                octal(&mut h[357..369], 1_700_000_000);
            })
            .finish();
        let bootstrap = build_layer(&tar);
        assert!(get_node(&bootstrap, "/etc/ld.so.preload").is_reg());
    }

    #[test]
    fn test_pax_path_and_linkpath_may_hold_newlines() {
        // PAX records are length-prefixed, so a value may contain '\n'.
        let tar = RawTar::default()
            .pax(b'x', &[("path", b"a\nb")])
            .reg("placeholder", b"data")
            .pax(b'x', &[("linkpath", b"x\ny")])
            .sym("s", "placeholder")
            .finish();
        let bootstrap = build_layer(&tar);
        assert_eq!(get_node(&bootstrap, "/a\nb").inode.size(), 4);
        assert!(bootstrap.tree.get_node(Path::new("/placeholder")).is_none());
        let s = get_node(&bootstrap, "/s");
        assert_eq!(s.info.symlink, Some(OsString::from("x\ny")));
    }

    #[test]
    fn test_pax_xattr_may_hold_newlines() {
        let tar = RawTar::default()
            .pax(
                b'x',
                &[
                    ("SCHILY.xattr.user.k", b"v\nw"),
                    ("SCHILY.xattr.user.other", b"z"),
                ],
            )
            .reg("f", b"data")
            .finish();
        let bootstrap = build_layer(&tar);
        let f = get_node(&bootstrap, "/f");
        assert_eq!(
            f.info
                .xattrs
                .get(OsStr::new("user.k"))
                .map(|v| v.as_slice()),
            Some(&b"v\nw"[..])
        );
        assert_eq!(
            f.info
                .xattrs
                .get(OsStr::new("user.other"))
                .map(|v| v.as_slice()),
            Some(&b"z"[..])
        );
    }

    #[test]
    fn test_pax_sparse_1_0_is_rejected() {
        // GNU sparse 1.0: the map is stored in front of the data, the real name in a record.
        let data = b"1\n0\n4\n".to_vec();
        let mut data = data;
        data.resize(512, 0);
        data.extend_from_slice(b"abcd");
        let tar = RawTar::default()
            .pax(
                b'x',
                &[
                    ("GNU.sparse.major", b"1"),
                    ("GNU.sparse.minor", b"0"),
                    ("GNU.sparse.name", b"sparse"),
                    ("GNU.sparse.realsize", b"8192"),
                ],
            )
            .reg("GNUSparseFile.0/sparse", &data)
            .finish();
        let err = build_layer_err(&tar);
        assert!(err.contains("sparse"), "{}", err);
    }

    #[test]
    fn test_pax_sparse_0_1_is_rejected() {
        let tar = RawTar::default()
            .pax(
                b'x',
                &[
                    ("GNU.sparse.size", b"8192"),
                    ("GNU.sparse.numblocks", b"1"),
                    ("GNU.sparse.map", b"4096,4"),
                ],
            )
            .reg("GNUSparseFile.0/sparse", b"abcd")
            .finish();
        let err = build_layer_err(&tar);
        assert!(err.contains("sparse"), "{}", err);
    }

    #[test]
    fn test_member_names_resolve_lexically_within_root() {
        let tar = RawTar::default()
            .reg("./a//b/../c", b"c")
            .reg("/etc/x", b"x")
            .reg("../escape", b"e")
            .reg("../../a/../up", b"u")
            .finish();
        let bootstrap = build_layer(&tar);
        assert_eq!(
            outline(&bootstrap),
            [
                "/ dir",
                "/a dir",
                "/a/c file",
                "/escape file",
                "/etc dir",
                "/etc/x file",
                "/up file",
            ]
        );
    }

    #[test]
    fn test_member_names_resolve_through_earlier_symlinks() {
        let tar = RawTar::default()
            .sym("a", "/")
            .reg("a/evil", b"1")
            .sym("b", "..")
            .reg("b/evil2", b"2")
            .dir("d/")
            .sym("l", "d")
            .reg("l/f", b"3")
            .sym("m", "../../d/../d")
            .reg("m/g", b"4")
            .finish();
        let bootstrap = build_layer(&tar);
        assert_eq!(
            outline(&bootstrap),
            [
                "/ dir",
                "/a symlink",
                "/b symlink",
                "/d dir",
                "/d/f file",
                "/d/g file",
                "/evil file",
                "/evil2 file",
                "/l symlink",
                "/m symlink",
            ]
        );
    }

    #[test]
    fn test_symlink_loop_is_rejected() {
        let tar = RawTar::default().sym("l", "l/x").reg("l/f", b"").finish();
        let err = build_layer_err(&tar);
        assert!(err.contains("symbolic links"), "{}", err);
    }

    #[test]
    fn test_parent_regular_file_is_rejected() {
        let tar = RawTar::default().reg("x", b"").reg("x/y", b"").finish();
        let err = build_layer_err(&tar);
        assert!(err.contains("not a directory"), "{}", err);
    }

    #[test]
    fn test_hardlink_target_resolves_through_symlink() {
        let tar = RawTar::default()
            .dir("etc/")
            .reg("etc/passwd", b"root")
            .sym("l", "/etc")
            .link("p", "l/passwd")
            .finish();
        let bootstrap = build_layer(&tar);
        let passwd = get_node(&bootstrap, "/etc/passwd");
        let p = get_node(&bootstrap, "/p");
        assert!(p.is_hardlink());
        assert_eq!(p.inode.ino(), passwd.inode.ino());
    }

    #[test]
    fn test_later_duplicate_member_wins() {
        let tar = RawTar::default()
            .reg("f", b"AAAA")
            .reg("f", b"BB")
            .dir("d/")
            .reg("d/x", b"")
            .reg("d", b"file")
            .dir("e/")
            .reg("e/y", b"")
            .dir("e/")
            .finish();
        let bootstrap = build_layer(&tar);
        assert_eq!(get_node(&bootstrap, "/f").inode.size(), 2);
        assert_eq!(
            outline(&bootstrap),
            ["/ dir", "/d file", "/e dir", "/e/y file", "/f file"]
        );
    }

    #[test]
    fn test_hardlink_keeps_inode_of_overwritten_target() {
        // The link names the inode holding "AAAA"; replacing `f` afterwards unlinks only `f`.
        let tar = RawTar::default()
            .reg("f", b"AAAA")
            .link("h", "f")
            .reg("f", b"BB")
            .finish();
        let bootstrap = build_layer(&tar);
        let f = get_node(&bootstrap, "/f");
        let h = get_node(&bootstrap, "/h");
        assert_eq!(f.inode.size(), 2);
        assert_eq!(h.inode.size(), 4);
        assert_ne!(f.inode.ino(), h.inode.ino());
        assert_eq!(f.inode.nlink(), 1);
        assert_eq!(h.inode.nlink(), 1);
    }

    #[test]
    fn test_root_member_is_ignored() {
        // Apply skips a member resolving to the root, so its metadata never lands.
        let tar = RawTar::default()
            .member(DIR, b"./", b"", 0o700, b"")
            .reg("f", b"")
            .finish();
        let bootstrap = build_layer(&tar);
        let root = get_node(&bootstrap, "/");
        assert_eq!(root.inode.mode() & 0o7777, 0o755);
    }

    #[test]
    fn test_pax_global_header_is_ignored() {
        // `git archive` writes one of these in front of every archive.
        let tar = RawTar::default()
            .member(
                b'g',
                b"pax_global_header",
                b"",
                0o666,
                &pax_record("comment", b"0123abcd"),
            )
            .reg("f", b"")
            .finish();
        let bootstrap = build_layer(&tar);
        assert_eq!(outline(&bootstrap), ["/ dir", "/f file"]);
    }

    #[test]
    fn test_header_only_members_have_no_data() {
        // Go reads no data for link, device, directory and fifo members whatever their size
        // field says, so the next header follows right after theirs.
        let mut tar = RawTar::default().sym("s", "f").reg("f", b"").finish();
        octal(&mut tar[124..136], 512);
        tar[148..156].fill(b' ');
        let sum: u64 = tar[..512].iter().map(|&b| b as u64).sum();
        tar[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
        let bootstrap = build_layer(&tar);
        assert_eq!(outline(&bootstrap), ["/ dir", "/f file", "/s symlink"]);
    }

    #[test]
    fn test_legacy_trailing_slash_member_is_directory() {
        // A type '\0' member whose name ends in '/' is a directory, as Go reads it.
        let tar = RawTar::default()
            .member(0, b"d/", b"", 0o750, b"")
            .reg("d/x", b"")
            .finish();
        let bootstrap = build_layer(&tar);
        assert_eq!(outline(&bootstrap), ["/ dir", "/d dir", "/d/x file"]);
        assert_eq!(get_node(&bootstrap, "/d").inode.mode() & 0o7777, 0o750);
    }

    #[test]
    fn test_members_after_end_of_archive_are_ignored() {
        let mut tar = RawTar::default().reg("f", b"").finish();
        tar.extend_from_slice(&RawTar::default().reg("hidden", b"").finish());
        let bootstrap = build_layer(&tar);
        assert_eq!(outline(&bootstrap), ["/ dir", "/f file"]);
    }

    #[test]
    fn test_tar_ref_chunk_offsets_follow_pax_headers() {
        // In tar-ref (and zran) mode chunks address the original stream, so a member read
        // through PAX headers must report the offset its data really has in the tar.
        let mut tar = pax_payload_tar();
        // Whatever follows the end-of-archive marker is no member, but still part of the blob.
        tar.extend_from_slice(&RawTar::default().reg("hidden", b"").finish());
        let (_tmp, mut ctx) = layer_ctx(&tar);
        ctx.conversion_type = ConversionType::TarToRef;
        ctx.blob_features.insert(BlobFeatures::SEPARATE);
        let tree = build_tree_as(&mut ctx, ConversionType::TarToRef).unwrap();
        let node = get_tree_node(&tree, "/long\nname");
        let offset = node.chunks[0].inner.compressed_offset() as usize;
        assert_eq!(&tar[offset..offset + 7], b"payload");
        assert!(tree.get_node(Path::new("/hidden")).is_none());
        assert_eq!(
            ctx.blob_tar_reader.as_ref().unwrap().position(),
            tar.len() as u64
        );
    }

    fn pax_payload_tar() -> Vec<u8> {
        RawTar::default()
            .pax(
                b'x',
                &[("path", b"long\nname"), ("SCHILY.xattr.user.k", b"v")],
            )
            .reg("placeholder", b"payload")
            .finish()
    }

    fn get_tree_node(tree: &Tree, path: &str) -> Node {
        tree.get_node(Path::new(path))
            .unwrap()
            .borrow_mut_node()
            .clone()
    }

    #[test]
    fn test_targz_ref_reads_members_through_pax_headers() {
        let tar = pax_payload_tar();
        let gz = compress::compress(&tar, compress::Algorithm::GZip)
            .unwrap()
            .0;
        let (_tmp, mut ctx) = layer_ctx(&gz);
        ctx.conversion_type = ConversionType::TargzToRef;
        ctx.blob_features.insert(BlobFeatures::SEPARATE);
        let tree = build_tree_as(&mut ctx, ConversionType::TargzToRef).unwrap();
        let node = get_tree_node(&tree, "/long\nname");
        assert_eq!(node.chunks.len(), 1);
        let chunk = &node.chunks[0].inner;
        assert!(chunk.is_compressed());
        assert_eq!(
            chunk.id(),
            &RafsDigest::from_buf(b"payload", digest::Algorithm::Sha256)
        );
    }

    #[test]
    fn test_missing_parent_sorting_before_a_sibling_holds_its_children() {
        // `root/` is synthesized after `tmp/` exists and sorts before it.
        let tar = RawTar::default()
            .reg("tmp/x", b"")
            .reg("root/.bashrc", b"")
            .finish();
        let bootstrap = build_layer(&tar);
        assert!(
            bootstrap
                .tree
                .get_node(Path::new("/root/.bashrc"))
                .is_some()
        );
        assert_eq!(
            bootstrap
                .tree
                .get_node(Path::new("/tmp"))
                .unwrap()
                .children
                .len(),
            1
        );
    }

    fn implicit_dirs(tree: &Tree) -> Vec<String> {
        let mut out = Vec::new();
        tree.walk_dfs_pre(&mut |t| {
            let node = t.borrow_mut_node();
            if node.inode.is_implicit_dir() {
                out.push(node.target().display().to_string());
            }
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn test_missing_parents_are_implicit_until_declared() {
        let tar = RawTar::default().reg("a/b/c", b"").dir("a/").finish();
        let bootstrap = build_layer(&tar);
        assert_eq!(implicit_dirs(&bootstrap.tree), ["/a/b"]);
        assert!(get_node(&bootstrap, "/a/b").is_dir());
    }

    // Builds the layer into a bootstrap file and loads the tree back from it.
    fn round_trip_layer(version: RafsVersion, tar: &[u8], with_blob: bool) -> Tree {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let tmp_dir = tmp_dir.as_path().to_path_buf();
        let source_path = tmp_dir.join("layer.tar");
        std::fs::write(&source_path, tar).unwrap();
        let mut ctx = create_context(source_path, version);
        if with_blob {
            ctx.blob_storage = Some(ArtifactStorage::FileDir((tmp_dir.clone(), String::new())));
        }
        let bootstrap_path = tmp_dir.join("bootstrap");
        let mut bootstrap_mgr = BootstrapManager::new(
            Some(ArtifactStorage::SingleFile(bootstrap_path.clone())),
            None,
        );
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        TarballBuilder::new(ConversionType::TarToRafs)
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
        let (rs, _) = nydus_rafs::metadata::RafsSuper::load_from_file(
            &bootstrap_path,
            Arc::new(nydus_api::ConfigV2::default()),
            false,
        )
        .unwrap();
        Tree::from_bootstrap(&rs, &mut ()).unwrap()
    }

    #[test]
    fn test_implicit_dir_flag_round_trips_v5() {
        let tar = RawTar::default().reg("a/b/c", b"").dir("a/").finish();
        let tree = round_trip_layer(RafsVersion::V5, &tar, false);
        assert_eq!(implicit_dirs(&tree), ["/a/b"]);
    }

    #[test]
    fn test_implicit_dir_flag_round_trips_v6() {
        let tar = RawTar::default().reg("a/b/c", b"").dir("a/").finish();
        let tree = round_trip_layer(RafsVersion::V6, &tar, false);
        assert_eq!(implicit_dirs(&tree), ["/a/b"]);
        assert!(!get_tree_node(&tree, "/a").inode.is_implicit_dir());

        // With file data the bootstrap carries a blob table, which moves the inode area.
        let tar = RawTar::default().reg("a/b/c", b"data").finish();
        let tree = round_trip_layer(RafsVersion::V6, &tar, true);
        assert_eq!(implicit_dirs(&tree), ["/a", "/a/b"]);
        assert_eq!(get_tree_node(&tree, "/a/b/c").inode.size(), 4);
    }
}
