// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Reading and writing images as **OCI Image Layout** tarballs.
//!
//! `nydusify copy` accepts `file://<path>` on either side: as a source it
//! imports an image from such a tarball, as a target it exports one. That is the
//! shape `containerd`'s import/export produces, and what the Go nydusify used
//! for its save/load flow, so archives round-trip between the two.
//!
//! The layout inside the tar is the one the OCI image-layout spec defines:
//!
//! ```text
//! oci-layout                  {"imageLayoutVersion": "1.0.0"}
//! index.json                  one manifest descriptor, tagged with the ref name
//! blobs/sha256/<hex>          manifest, config and every layer, by digest
//! ```
//!
//! Blobs are streamed through a staging directory rather than buffered: a nydus
//! data blob is routinely hundreds of megabytes, and an image can hold many.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use registry_client::Descriptor;
use registry_client::types::{Index, Manifest, verify_digest};
use tracing::debug;

/// Marker file every OCI layout carries, and the only version we emit.
const OCI_LAYOUT_FILE: &str = "oci-layout";
const OCI_LAYOUT_VERSION: &str = "1.0.0";
const INDEX_FILE: &str = "index.json";
/// Annotation carrying the image reference an archive entry was saved under.
const ANNOTATION_REF_NAME: &str = "org.opencontainers.image.ref.name";

/// The local path behind a `file://` reference, or `None` for a registry ref.
///
/// `file://./rel` and `file:///abs` are both accepted, matching the Go tool;
/// the path is resolved against the current directory so callers get an
/// absolute one either way.
pub fn local_path(reference: &str) -> Result<Option<PathBuf>> {
    let Some(rest) = reference.strip_prefix("file://") else {
        return Ok(None);
    };
    if rest.is_empty() {
        bail!("file:// reference has no path");
    }
    let path = PathBuf::from(rest);
    let abs = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .context("resolve the current directory for a relative file:// path")?
            .join(path)
    };
    Ok(Some(abs))
}

/// An image read out of an OCI layout tarball.
#[derive(Debug)]
pub struct ImportedImage {
    /// Raw manifest JSON.
    pub manifest_bytes: Vec<u8>,
    /// The manifest's own descriptor (digest, size, media type).
    pub descriptor: Descriptor,
    /// Parsed manifest, for walking config and layers.
    pub manifest: Manifest,
    /// Reference the archive recorded, when it carried one.
    pub ref_name: Option<String>,
    /// Directory holding the unpacked `blobs/sha256/<hex>` files.
    blobs_dir: PathBuf,
}

impl ImportedImage {
    /// On-disk path of a blob named by `digest`.
    pub fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        let hex = digest
            .strip_prefix("sha256:")
            .with_context(|| format!("unsupported digest algorithm in {digest}"))?;
        let path = self.blobs_dir.join("sha256").join(hex);
        if !path.is_file() {
            bail!("archive is missing blob {digest}");
        }
        Ok(path)
    }
}

/// Unpack an OCI layout tarball into `dest` and resolve its single image.
///
/// `dest` is expected to be an empty staging directory owned by the caller.
pub fn import(archive: &Path, dest: &Path) -> Result<ImportedImage> {
    let file = std::fs::File::open(archive)
        .with_context(|| format!("open archive {}", archive.display()))?;
    // Accept a gzip'd archive too: `docker save | gzip` is a common shape and
    // the Go tool's import decompresses transparently.
    let mut probe = [0u8; 2];
    let gzipped = {
        use std::io::Read as _;
        let mut f = std::fs::File::open(archive)?;
        f.read_exact(&mut probe).is_ok() && probe == [0x1f, 0x8b]
    };
    if gzipped {
        let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(file));
        unpack_sanitized(&mut ar, dest)?;
    } else {
        let mut ar = tar::Archive::new(file);
        unpack_sanitized(&mut ar, dest)?;
    }

    let index_bytes = std::fs::read(dest.join(INDEX_FILE))
        .with_context(|| format!("archive {} has no {INDEX_FILE}", archive.display()))?;
    let index: Index = serde_json::from_slice(&index_bytes)
        .with_context(|| format!("parse {INDEX_FILE} in {}", archive.display()))?;

    let descriptor = index
        .manifests
        .first()
        .cloned()
        .with_context(|| format!("archive {} lists no manifests", archive.display()))?;
    if index.manifests.len() > 1 {
        debug!(
            count = index.manifests.len(),
            "archive holds several manifests; importing the first"
        );
    }

    let blobs_dir = dest.join("blobs");
    let hex = descriptor
        .digest
        .strip_prefix("sha256:")
        .with_context(|| format!("unsupported digest algorithm in {}", descriptor.digest))?;
    let manifest_path = blobs_dir.join("sha256").join(hex);
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("read manifest blob {}", manifest_path.display()))?;
    verify_digest(&manifest_bytes, &descriptor.digest)
        .context("archive manifest does not match the digest index.json records")?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).context("parse archive manifest")?;

    let ref_name = descriptor
        .annotations
        .as_ref()
        .and_then(|a| a.get(ANNOTATION_REF_NAME))
        .cloned();

    Ok(ImportedImage {
        manifest_bytes,
        descriptor,
        manifest,
        ref_name,
        blobs_dir,
    })
}

/// Unpack `archive` into `dest`, refusing entries that escape it.
///
/// A tarball is untrusted input; without this a `../` entry would let it write
/// anywhere the process can (the classic Zip-Slip).
fn unpack_sanitized<R: std::io::Read>(archive: &mut tar::Archive<R>, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("create archive staging dir {}", dest.display()))?;
    for entry in archive.entries().context("read archive entries")? {
        let mut entry = entry.context("read archive entry")?;
        let path = entry.path().context("archive entry path")?.into_owned();
        if path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        }) {
            bail!("archive entry {:?} escapes the extraction directory", path);
        }
        entry
            .unpack_in(dest)
            .with_context(|| format!("unpack archive entry {:?}", path))?;
    }
    Ok(())
}

/// A blob to place in an exported archive.
pub struct ArchiveBlob {
    pub digest: String,
    pub size: u64,
    /// Staged file holding the blob's bytes.
    pub path: PathBuf,
}

/// Write an OCI layout tarball containing `manifest` and `blobs`.
///
/// `ref_name` is recorded on the manifest descriptor so a later import (or
/// `containerd image import`) knows what the image was called.
pub fn export(
    out: &Path,
    manifest_bytes: &[u8],
    manifest_media_type: &str,
    ref_name: &str,
    blobs: &[ArchiveBlob],
) -> Result<()> {
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create archive directory {}", parent.display()))?;
    }
    let file =
        std::fs::File::create(out).with_context(|| format!("create archive {}", out.display()))?;
    let mut builder = tar::Builder::new(file);

    let layout = format!("{{\"imageLayoutVersion\":\"{OCI_LAYOUT_VERSION}\"}}");
    append_bytes(&mut builder, OCI_LAYOUT_FILE, layout.as_bytes())?;

    let manifest_digest = registry_client::types::sha256_digest(manifest_bytes);
    let mut annotations = std::collections::BTreeMap::new();
    annotations.insert(ANNOTATION_REF_NAME.to_string(), ref_name.to_string());
    let manifest_desc = Descriptor {
        media_type: manifest_media_type.to_string(),
        digest: manifest_digest.clone(),
        size: manifest_bytes.len() as u64,
        annotations: Some(annotations),
        ..Descriptor::default()
    };
    let index = Index {
        schema_version: 2,
        media_type: Some(registry_client::types::MEDIA_TYPE_OCI_INDEX.to_string()),
        manifests: vec![manifest_desc],
        ..Index::default()
    };
    let index_bytes = serde_json::to_vec(&index).context("serialize archive index.json")?;
    append_bytes(&mut builder, INDEX_FILE, &index_bytes)?;

    append_bytes(
        &mut builder,
        &blob_entry_path(&manifest_digest)?,
        manifest_bytes,
    )?;
    for blob in blobs {
        let name = blob_entry_path(&blob.digest)?;
        let mut f = std::fs::File::open(&blob.path)
            .with_context(|| format!("open blob {} for archiving", blob.path.display()))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(blob.size);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, &name, &mut f)
            .with_context(|| format!("append blob {} to the archive", blob.digest))?;
    }

    builder.into_inner().context("finish archive")?.flush()?;
    Ok(())
}

/// `blobs/sha256/<hex>` path for a digest.
fn blob_entry_path(digest: &str) -> Result<String> {
    let hex = digest
        .strip_prefix("sha256:")
        .with_context(|| format!("unsupported digest algorithm in {digest}"))?;
    Ok(format!("blobs/sha256/{hex}"))
}

fn append_bytes<W: Write>(builder: &mut tar::Builder<W>, name: &str, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, name, bytes)
        .with_context(|| format!("append {name} to the archive"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_client::types::{MEDIA_TYPE_OCI_MANIFEST, sha256_digest};

    fn staged(dir: &Path, name: &str, bytes: &[u8]) -> ArchiveBlob {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        ArchiveBlob {
            digest: sha256_digest(bytes),
            size: bytes.len() as u64,
            path,
        }
    }

    fn sample_manifest(config: &ArchiveBlob, layer: &ArchiveBlob) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MEDIA_TYPE_OCI_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config.digest,
                "size": config.size,
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer.digest,
                "size": layer.size,
            }],
        }))
        .unwrap()
    }

    #[test]
    fn file_refs_resolve_to_absolute_paths() {
        assert_eq!(
            local_path("file:///tmp/image.tar").unwrap(),
            Some(PathBuf::from("/tmp/image.tar"))
        );
        // A registry reference is left alone.
        assert_eq!(local_path("localhost:5077/redis:7.0.1").unwrap(), None);
        // Relative paths become absolute rather than depending on the cwd later.
        let rel = local_path("file://./out.tar").unwrap().unwrap();
        assert!(rel.is_absolute());
        assert!(rel.ends_with("out.tar"));
        // An empty path is a mistake worth naming.
        assert!(local_path("file://").is_err());
    }

    #[test]
    fn export_then_import_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let config = staged(dir.path(), "config", b"{\"architecture\":\"amd64\"}");
        let layer = staged(dir.path(), "layer", b"layer-bytes-here");
        let manifest_bytes = sample_manifest(&config, &layer);

        let archive = dir.path().join("saved.tar");
        export(
            &archive,
            &manifest_bytes,
            MEDIA_TYPE_OCI_MANIFEST,
            "localhost:5077/app:nydus",
            &[config, layer],
        )
        .unwrap();

        let dest = dir.path().join("unpacked");
        let imported = import(&archive, &dest).unwrap();

        assert_eq!(imported.manifest_bytes, manifest_bytes);
        assert_eq!(
            imported.ref_name.as_deref(),
            Some("localhost:5077/app:nydus")
        );
        assert_eq!(imported.manifest.layers.len(), 1);
        // Every blob the manifest names is present and intact.
        let cfg = imported
            .blob_path(&imported.manifest.config.digest)
            .unwrap();
        assert_eq!(
            std::fs::read(cfg).unwrap(),
            b"{\"architecture\":\"amd64\"}".to_vec()
        );
        let lyr = imported
            .blob_path(&imported.manifest.layers[0].digest)
            .unwrap();
        assert_eq!(std::fs::read(lyr).unwrap(), b"layer-bytes-here".to_vec());
    }

    #[test]
    fn import_rejects_a_tampered_manifest() {
        // index.json records the manifest digest; a mismatch means the archive
        // was altered, and importing it would push something else entirely.
        let dir = tempfile::tempdir().unwrap();
        let config = staged(dir.path(), "config", b"{}");
        let layer = staged(dir.path(), "layer", b"l");
        let manifest_bytes = sample_manifest(&config, &layer);
        let archive = dir.path().join("saved.tar");
        export(
            &archive,
            &manifest_bytes,
            MEDIA_TYPE_OCI_MANIFEST,
            "app:v1",
            &[config, layer],
        )
        .unwrap();

        let dest = dir.path().join("unpacked");
        import(&archive, &dest).unwrap();
        // Corrupt the manifest blob in place, then re-import from the directory
        // by rebuilding an archive around the tampered bytes.
        let hex = sha256_digest(&manifest_bytes)
            .strip_prefix("sha256:")
            .unwrap()
            .to_string();
        let manifest_blob = dest.join("blobs").join("sha256").join(&hex);
        std::fs::write(&manifest_blob, b"{\"schemaVersion\":2}").unwrap();

        let repacked = dir.path().join("tampered.tar");
        {
            let f = std::fs::File::create(&repacked).unwrap();
            let mut b = tar::Builder::new(f);
            b.append_dir_all(".", &dest).unwrap();
            b.into_inner().unwrap();
        }
        let err = import(&repacked, &dir.path().join("unpacked2")).unwrap_err();
        assert!(
            format!("{err:#}").contains("digest"),
            "expected a digest mismatch, got: {err:#}"
        );
    }

    #[test]
    fn import_refuses_entries_that_escape_the_destination() {
        // The tar crate refuses to *write* a `..` path, so the malicious entry
        // is built by poking the raw header name -- which is exactly what a
        // hostile archive would contain.
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil.tar");
        let data = b"pwned";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        {
            let name = &mut header.as_gnu_mut().unwrap().name;
            let evil = b"../escaped";
            name[..evil.len()].copy_from_slice(evil);
        }
        header.set_cksum();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(data);
        bytes.resize(bytes.len().div_ceil(512) * 512, 0);
        bytes.extend_from_slice(&[0u8; 1024]); // two zero blocks terminate a tar
        std::fs::write(&archive, &bytes).unwrap();

        let err = import(&archive, &dir.path().join("dest")).unwrap_err();
        assert!(
            format!("{err:#}").contains("escapes"),
            "expected the traversal guard to fire, got: {err:#}"
        );
        assert!(
            !dir.path().join("escaped").exists(),
            "the entry must not have been written outside the destination"
        );
    }
}
