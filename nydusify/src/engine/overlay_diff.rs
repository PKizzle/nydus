// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Translate an overlayfs *upper* directory into an OCI layer tar.
//!
//! `nydusify commit` snapshots a running container by taking the read-write
//! layer containerd handed the runtime — the overlay `upperdir` — and publishing
//! it as one more layer on top of the container's nydus image. The upperdir
//! speaks overlayfs' deletion vocabulary; an OCI layer speaks its own. Every
//! entry is translated on the way out:
//!
//! | upperdir                                  | OCI layer                     |
//! |-------------------------------------------|-------------------------------|
//! | character device, rdev 0/0                | `.wh.<name>`, an empty file   |
//! | directory with `overlay.opaque` = `y`     | the dir + `.wh..wh..opq` in it |
//! | anything else                             | copied through                |
//!
//! `overlay.*` xattrs are the kernel's own bookkeeping and never belong in a
//! published layer, so they are stripped; every other xattr is carried across as
//! a `SCHILY.xattr.*` PAX record, which `nydus-image` reads back (see
//! `builder/src/tarball.rs`).
//!
//! ## Deliberately unsupported
//!
//! Two overlayfs features rewrite where a file's *data* lives, and neither can
//! be honoured from the upperdir alone:
//!
//! - `overlay.redirect` — the directory's lower counterpart lives under a
//!   different name (set when a directory is renamed, `redirect_dir=on`).
//!   Emitting the upper contents alone would leave the pre-rename directory
//!   visible in the committed image.
//! - `overlay.metacopy` — the upper entry carries metadata only, and its
//!   contents still live in a lower layer (`metacopy=on`). Copying the upper
//!   file would publish a zero-length file.
//!
//! containerd's overlay snapshotter enables neither, so in practice they do not
//! appear. If one does, [`write_upper_layer_tar`] fails loudly rather than
//! silently committing a wrong layer.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::{self, BufWriter};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tar::{Builder, EntryType, Header, HeaderMode};
use tracing::{debug, warn};

/// OCI whiteout prefix: `.wh.<name>` deletes `<name>` from the lower layers.
pub const OCI_WHITEOUT_PREFIX: &str = ".wh.";
/// OCI opaque marker: hides every lower entry of the directory holding it.
pub const OCI_WHITEOUT_OPAQUE: &str = ".wh..wh..opq";

/// The two namespaces overlayfs keeps its bookkeeping xattrs in. `trusted.` is
/// used by privileged mounts, `user.` by unprivileged ones (`userxattr`).
const OVERLAY_XATTR_NAMESPACES: [&str; 2] = ["trusted.overlay.", "user.overlay."];

/// PAX record prefix for a per-entry extended attribute — the convention
/// `nydus-image`'s tar reader keys on.
const PAX_XATTR_PREFIX: &str = "SCHILY.xattr.";

/// The only xattr namespaces RAFS can store — kept in step with
/// `RAFS_XATTR_PREFIXES` in `rafs/src/metadata/layout/mod.rs`. `nydus-image`
/// rejects anything else outright (`RafsXAttrs::add` returns `EINVAL`, and the
/// build fails with a bare "invalid xattr key"), so an attribute outside them is
/// dropped here with a warning rather than taking the whole commit down.
const RAFS_XATTR_PREFIXES: [&str; 5] = [
    "user.",
    "security.",
    "trusted.",
    "system.posix_acl_access",
    "system.posix_acl_default",
];

/// What [`write_upper_layer_tar`] found while walking the upperdir. Logged by
/// the caller so an empty or surprising commit is visible in the output.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiffStats {
    /// Regular files, symlinks, fifos and device nodes copied through.
    pub files: u64,
    /// Directories copied through.
    pub directories: u64,
    /// `.wh.<name>` markers emitted for overlayfs deletions.
    pub whiteouts: u64,
    /// `.wh..wh..opq` markers emitted for opaque directories.
    pub opaque_dirs: u64,
    /// Unix sockets skipped — they have no tar representation.
    pub skipped_sockets: u64,
}

impl DiffStats {
    /// Whether the walk produced no layer content at all. A commit of an empty
    /// diff still succeeds (it republishes the base image plus an empty layer),
    /// but it is worth saying out loud.
    pub fn is_empty(&self) -> bool {
        self.files == 0 && self.directories == 0 && self.whiteouts == 0 && self.opaque_dirs == 0
    }
}

/// Write the OCI layer tar for `upper_dir` to `out`, returning what was found.
///
/// The tar is uncompressed and parent-first (a directory is always written
/// before its contents), which is what `nydus-image create --type tar-rafs`
/// expects.
pub fn write_upper_layer_tar(upper_dir: &Path, out: &Path) -> Result<DiffStats> {
    let file =
        File::create(out).with_context(|| format!("create upper-layer tar {}", out.display()))?;
    let mut builder = Builder::new(BufWriter::new(file));
    // Preserve uid/gid/mtime, and never dereference a symlink: the container
    // may well have written a dangling one, and following it would publish the
    // wrong content (or fail).
    builder.mode(HeaderMode::Complete);
    builder.follow_symlinks(false);

    let mut stats = DiffStats::default();
    append_dir_contents(&mut builder, upper_dir, Path::new(""), &mut stats)?;

    builder
        .into_inner()
        .and_then(|w| w.into_inner().map_err(io::Error::from))
        .with_context(|| format!("finish upper-layer tar {}", out.display()))?;
    Ok(stats)
}

/// Walk one directory of the upperdir, emitting its entries in sorted order.
///
/// Sorting is not cosmetic: it makes the layer — and therefore the layer digest
/// and the committed image digest — reproducible for an unchanged upperdir,
/// which `readdir` order alone does not give.
fn append_dir_contents<W: io::Write>(
    builder: &mut Builder<W>,
    upper_root: &Path,
    rel: &Path,
    stats: &mut DiffStats,
) -> Result<()> {
    let abs = upper_root.join(rel);
    let mut names: Vec<PathBuf> = fs::read_dir(&abs)
        .with_context(|| format!("read upper directory {}", abs.display()))?
        .map(|entry| {
            entry
                .map(|e| PathBuf::from(e.file_name()))
                .with_context(|| format!("read entry of {}", abs.display()))
        })
        .collect::<Result<_>>()?;
    names.sort();

    for name in names {
        let child_rel = rel.join(&name);
        let child_abs = upper_root.join(&child_rel);
        let md = fs::symlink_metadata(&child_abs)
            .with_context(|| format!("stat {}", child_abs.display()))?;

        reject_unsupported_markers(&child_abs, &child_rel)?;

        if is_whiteout(&md) {
            append_whiteout(builder, &child_rel)?;
            stats.whiteouts += 1;
            continue;
        }
        if md.file_type().is_socket() {
            // A socket has no tar entry type. Nothing downstream can recreate
            // it, and failing the whole commit over one would be worse than
            // dropping it — the container recreates its sockets on start.
            warn!(path = %child_rel.display(), "skipping unix socket: not representable in a tar layer");
            stats.skipped_sockets += 1;
            continue;
        }

        append_entry(builder, &child_abs, &child_rel)?;

        if md.is_dir() {
            stats.directories += 1;
            if is_opaque_dir(&child_abs)? {
                append_opaque_marker(builder, &child_rel)?;
                stats.opaque_dirs += 1;
            }
            append_dir_contents(builder, upper_root, &child_rel, stats)?;
        } else {
            stats.files += 1;
        }
    }
    Ok(())
}

/// Copy one upperdir entry into the layer, xattrs included.
fn append_entry<W: io::Write>(builder: &mut Builder<W>, abs: &Path, rel: &Path) -> Result<()> {
    append_pax_xattrs(builder, abs, rel)?;
    builder
        .append_path_with_name(abs, rel)
        .with_context(|| format!("append {} to the upper layer", rel.display()))
}

/// Emit the entry's non-overlayfs xattrs as a PAX header. PAX extended headers
/// apply to the record that follows, so this must be written immediately before
/// the entry itself.
fn append_pax_xattrs<W: io::Write>(builder: &mut Builder<W>, abs: &Path, rel: &Path) -> Result<()> {
    let xattrs = collect_xattrs(abs)?;
    if xattrs.is_empty() {
        return Ok(());
    }
    debug!(path = %rel.display(), count = xattrs.len(), "carrying xattrs into the layer");
    builder
        .append_pax_extensions(xattrs.iter().map(|(k, v)| (k.as_str(), v.as_slice())))
        .with_context(|| format!("append xattrs of {}", rel.display()))
}

/// Read every xattr of `path` that belongs in the published layer, keyed by its
/// PAX record name. Symlinks are not dereferenced.
fn collect_xattrs(path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    let names = match xattr::list(path) {
        Ok(names) => names,
        Err(e) if is_absent_or_unsupported(&e) => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("list xattrs of {}", path.display())),
    };
    for name in names {
        let Some(key) = name.to_str() else {
            warn!(path = %path.display(), "skipping xattr with a non-UTF-8 name");
            continue;
        };
        if is_overlay_xattr(key) {
            continue;
        }
        if !is_storable_xattr(key) {
            warn!(
                path = %path.display(),
                xattr = key,
                "dropping xattr: RAFS stores only the user./security./trusted./posix_acl namespaces"
            );
            continue;
        }
        match xattr::get(path, &name) {
            Ok(Some(value)) => {
                out.insert(format!("{PAX_XATTR_PREFIX}{key}"), value);
            }
            // Raced with the container removing the attribute between list and
            // get; nothing to carry across.
            Ok(None) => {}
            Err(e) if is_absent_or_unsupported(&e) => {}
            Err(e) => {
                return Err(e).with_context(|| format!("read xattr {key} of {}", path.display()));
            }
        }
    }
    Ok(out)
}

/// `.wh.<name>` — an empty regular file standing in for a deleted lower entry.
fn append_whiteout<W: io::Write>(builder: &mut Builder<W>, rel: &Path) -> Result<()> {
    let name = rel
        .file_name()
        .with_context(|| format!("whiteout {} has no file name", rel.display()))?;
    let mut marker = rel.to_path_buf();
    marker.set_file_name(format!(
        "{OCI_WHITEOUT_PREFIX}{}",
        Path::new(name).display()
    ));
    debug!(path = %rel.display(), "overlayfs deletion -> OCI whiteout");
    append_empty_file(builder, &marker)
}

/// `.wh..wh..opq` inside a directory whose lower contents are all hidden.
fn append_opaque_marker<W: io::Write>(builder: &mut Builder<W>, rel: &Path) -> Result<()> {
    debug!(path = %rel.display(), "opaque directory -> OCI opaque marker");
    append_empty_file(builder, &rel.join(OCI_WHITEOUT_OPAQUE))
}

fn append_empty_file<W: io::Write>(builder: &mut Builder<W>, rel: &Path) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    builder
        .append_data(&mut header, rel, io::empty())
        .with_context(|| format!("append marker {}", rel.display()))
}

/// An overlayfs deletion marker: a character device with device number 0/0.
fn is_whiteout(md: &Metadata) -> bool {
    md.file_type().is_char_device() && md.rdev() == 0
}

/// Whether the directory hides everything below it (`overlay.opaque` = `"y"`).
fn is_opaque_dir(path: &Path) -> Result<bool> {
    for namespace in OVERLAY_XATTR_NAMESPACES {
        if read_overlay_xattr(path, namespace, "opaque")?.as_deref() == Some(b"y") {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Fail on the two overlayfs markers whose meaning cannot be reconstructed from
/// the upperdir alone (see the module docs).
fn reject_unsupported_markers(abs: &Path, rel: &Path) -> Result<()> {
    for namespace in OVERLAY_XATTR_NAMESPACES {
        for (marker, what) in [
            (
                "redirect",
                "was renamed from another path (overlayfs redirect_dir=on)",
            ),
            (
                "metacopy",
                "keeps its contents in a lower layer (overlayfs metacopy=on)",
            ),
        ] {
            if read_overlay_xattr(abs, namespace, marker)?.is_some() {
                bail!(
                    "cannot commit {}: it {what}, which nydusify cannot reconstruct \
                     from the upper directory alone. Remount the container's \
                     snapshotter without that overlayfs option, or commit from a \
                     container that has not triggered it.",
                    rel.display(),
                );
            }
        }
    }
    Ok(())
}

fn read_overlay_xattr(path: &Path, namespace: &str, marker: &str) -> Result<Option<Vec<u8>>> {
    let key = format!("{namespace}{marker}");
    match xattr::get(path, &key) {
        Ok(value) => Ok(value),
        Err(e) if is_absent_or_unsupported(&e) => Ok(None),
        // Anything else — EPERM on the `trusted.` namespace, say — would make
        // us miss a marker and publish a wrong layer, so it is fatal.
        Err(e) => Err(e).with_context(|| format!("read xattr {key} of {}", path.display())),
    }
}

fn is_overlay_xattr(key: &str) -> bool {
    OVERLAY_XATTR_NAMESPACES
        .iter()
        .any(|ns| key.starts_with(ns))
}

/// Whether RAFS can store an attribute under this key at all.
fn is_storable_xattr(key: &str) -> bool {
    RAFS_XATTR_PREFIXES.iter().any(|p| key.starts_with(p))
}

/// Whether an xattr error means "there is nothing there" rather than "the read
/// failed": the attribute is absent (`ENODATA`/`ENOATTR`) or the filesystem has
/// no xattr support at all (`ENOTSUP`).
fn is_absent_or_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENODATA) | Some(libc::ENOTSUP) | Some(libc::ENOSYS)
    ) || e.kind() == io::ErrorKind::NotFound
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    /// Every entry in the produced tar, as `(path, entry_type, size)`.
    fn read_tar(path: &Path) -> Vec<(String, EntryType, u64)> {
        let mut archive = tar::Archive::new(File::open(path).unwrap());
        archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.path().unwrap().to_string_lossy().into_owned(),
                    e.header().entry_type(),
                    e.header().size().unwrap(),
                )
            })
            .collect()
    }

    fn paths(entries: &[(String, EntryType, u64)]) -> Vec<&str> {
        entries.iter().map(|(p, _, _)| p.as_str()).collect()
    }

    #[test]
    fn copies_files_and_directories_parent_first_in_sorted_order() {
        let upper = tempfile::tempdir().unwrap();
        fs::create_dir_all(upper.path().join("root/sub")).unwrap();
        fs::write(upper.path().join("root/sub/b.txt"), b"second").unwrap();
        fs::write(upper.path().join("root/a.txt"), b"first").unwrap();
        let out = upper.path().parent().unwrap().join("upper-sorted.tar");

        let stats = write_upper_layer_tar(upper.path(), &out).unwrap();

        assert_eq!(stats.directories, 2);
        assert_eq!(stats.files, 2);
        assert!(!stats.is_empty());
        let entries = read_tar(&out);
        assert_eq!(
            paths(&entries),
            vec!["root", "root/a.txt", "root/sub", "root/sub/b.txt"],
        );
        // Directories are marked by the header type flag, not a trailing
        // slash -- which is what `nydus-image` keys on (builder/src/tarball.rs).
        assert_eq!(entries[0].1, EntryType::Directory);
        assert_eq!(entries[1].1, EntryType::Regular);
        assert_eq!(entries[1].2, 5);
        fs::remove_file(&out).unwrap();
    }

    #[test]
    fn an_untouched_upperdir_produces_an_empty_layer() {
        let upper = tempfile::tempdir().unwrap();
        let out = upper.path().parent().unwrap().join("upper-empty.tar");

        let stats = write_upper_layer_tar(upper.path(), &out).unwrap();

        assert!(stats.is_empty());
        assert!(read_tar(&out).is_empty());
        fs::remove_file(&out).unwrap();
    }

    #[test]
    fn symlinks_are_recorded_not_followed() {
        let upper = tempfile::tempdir().unwrap();
        fs::write(upper.path().join("target.txt"), b"payload").unwrap();
        std::os::unix::fs::symlink("target.txt", upper.path().join("link")).unwrap();
        // A dangling symlink must not abort the walk either.
        std::os::unix::fs::symlink("/nowhere", upper.path().join("dangling")).unwrap();
        let out = upper.path().parent().unwrap().join("upper-symlink.tar");

        write_upper_layer_tar(upper.path(), &out).unwrap();

        let entries = read_tar(&out);
        assert_eq!(paths(&entries), vec!["dangling", "link", "target.txt"]);
        assert_eq!(entries[0].1, EntryType::Symlink);
        assert_eq!(entries[1].1, EntryType::Symlink);
        // A followed symlink would have copied the 7-byte payload.
        assert_eq!(entries[1].2, 0);
        fs::remove_file(&out).unwrap();
    }

    #[test]
    fn opaque_directories_get_an_opq_marker_before_their_contents() {
        let upper = tempfile::tempdir().unwrap();
        let opaque = upper.path().join("etc");
        fs::create_dir(&opaque).unwrap();
        fs::write(opaque.join("hosts"), b"127.0.0.1").unwrap();
        // `trusted.` needs privilege; `user.` is the unprivileged namespace and
        // exercises the same code path.
        if xattr::set(&opaque, "user.overlay.opaque", b"y").is_err() {
            eprintln!("skipping: filesystem does not support user xattrs");
            return;
        }
        let out = upper.path().parent().unwrap().join("upper-opaque.tar");

        let stats = write_upper_layer_tar(upper.path(), &out).unwrap();

        assert_eq!(stats.opaque_dirs, 1);
        let entries = read_tar(&out);
        assert_eq!(
            paths(&entries),
            vec!["etc", "etc/.wh..wh..opq", "etc/hosts"],
        );
        assert_eq!(entries[1].1, EntryType::Regular);
        assert_eq!(entries[1].2, 0);
        fs::remove_file(&out).unwrap();
    }

    #[test]
    fn overlay_bookkeeping_xattrs_are_stripped_and_the_rest_carried_over() {
        let upper = tempfile::tempdir().unwrap();
        let file = upper.path().join("payload");
        fs::write(&file, b"data").unwrap();
        if xattr::set(&file, "user.mykey", b"myvalue").is_err() {
            eprintln!("skipping: filesystem does not support user xattrs");
            return;
        }
        // `user.overlay.impure` is overlayfs bookkeeping and must not travel.
        xattr::set(&file, "user.overlay.impure", b"y").unwrap();
        let out = upper.path().parent().unwrap().join("upper-xattr.tar");

        write_upper_layer_tar(upper.path(), &out).unwrap();

        let mut archive = tar::Archive::new(File::open(&out).unwrap());
        let mut records = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if let Some(exts) = entry.pax_extensions().unwrap() {
                for ext in exts {
                    let ext = ext.unwrap();
                    records.push((
                        ext.key().unwrap().to_string(),
                        String::from_utf8_lossy(ext.value_bytes()).into_owned(),
                    ));
                }
            }
        }
        assert!(
            records.contains(&("SCHILY.xattr.user.mykey".to_string(), "myvalue".to_string())),
            "user xattr did not travel: {records:?}",
        );
        assert!(
            !records.iter().any(|(k, _)| k.contains("overlay")),
            "overlayfs bookkeeping leaked into the layer: {records:?}",
        );
        fs::remove_file(&out).unwrap();
    }

    #[test]
    fn a_redirect_marker_fails_the_commit_instead_of_producing_a_wrong_layer() {
        let upper = tempfile::tempdir().unwrap();
        let renamed = upper.path().join("newname");
        fs::create_dir(&renamed).unwrap();
        if xattr::set(&renamed, "user.overlay.redirect", b"/oldname").is_err() {
            eprintln!("skipping: filesystem does not support user xattrs");
            return;
        }
        let out = upper.path().parent().unwrap().join("upper-redirect.tar");

        let err = write_upper_layer_tar(upper.path(), &out).unwrap_err();

        assert!(
            err.to_string().contains("newname") && err.to_string().contains("redirect_dir"),
            "unexpected error: {err}",
        );
        let _ = fs::remove_file(&out);
    }

    #[test]
    fn whiteout_names_are_derived_from_the_deleted_entry() {
        // The char-device 0/0 form needs root, so exercise the name derivation
        // directly — it is the part that is easy to get wrong.
        let mut buf = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            append_whiteout(&mut builder, Path::new("root/gone.txt")).unwrap();
            append_whiteout(&mut builder, Path::new("top")).unwrap();
            builder.finish().unwrap();
        }
        let mut archive = tar::Archive::new(&buf[..]);
        let found: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(found, vec!["root/.wh.gone.txt", ".wh.top"]);
    }

    #[test]
    fn whiteout_detection_keys_on_a_zero_device_number() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        fs::write(&plain, b"x").unwrap();
        let md = fs::symlink_metadata(&plain).unwrap();
        assert!(!is_whiteout(&md));

        // /dev/null is char 1/3 — a character device that is NOT a whiteout.
        if let Ok(md) = fs::symlink_metadata("/dev/null") {
            assert!(md.file_type().is_char_device());
            assert!(!is_whiteout(&md));
        }
    }

    #[test]
    fn empty_markers_carry_no_payload() {
        let mut buf = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            append_opaque_marker(&mut builder, Path::new("var/lib")).unwrap();
            builder.finish().unwrap();
        }
        let mut archive = tar::Archive::new(&buf[..]);
        let mut entries = archive.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        assert_eq!(
            entry.path().unwrap().to_str().unwrap(),
            "var/lib/.wh..wh..opq"
        );
        let mut content = Vec::new();
        entry.read_to_end(&mut content).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn only_xattrs_rafs_can_store_are_carried_over() {
        // Anything outside these namespaces makes `nydus-image` abort the whole
        // build with "invalid xattr key", so it must never reach the tar.
        assert!(is_storable_xattr("user.mykey"));
        assert!(is_storable_xattr("security.capability"));
        assert!(is_storable_xattr("trusted.something"));
        assert!(is_storable_xattr("system.posix_acl_access"));
        assert!(is_storable_xattr("system.posix_acl_default"));
        assert!(!is_storable_xattr("system.nfs4_acl"));
        assert!(!is_storable_xattr("com.apple.provenance"));
        assert!(!is_storable_xattr("btrfs.compression"));
    }

    #[test]
    fn overlay_xattr_classification_covers_both_namespaces() {
        assert!(is_overlay_xattr("trusted.overlay.opaque"));
        assert!(is_overlay_xattr("user.overlay.redirect"));
        assert!(!is_overlay_xattr("user.overlayfsish"));
        assert!(!is_overlay_xattr("security.capability"));
        assert!(!is_overlay_xattr("user.mykey"));
    }
}
