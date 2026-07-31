// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Packaging of the RAFS bootstrap as an OCI image layer.
//!
//! The bootstrap is published as an **ordinary gzip'd tar layer** whose single
//! entry is `image/image.boot`, annotated `containerd.io/snapshot/nydus-bootstrap`.
//! That is the shape the Go nydusify and upstream's v3 converter publish, and it
//! is what the rest of this project already expects:
//!
//! * containerd unpacks it with its normal tar+gzip path, so no stream processor
//!   has to be registered for a custom media type;
//! * the snapshotter then reads the bootstrap from
//!   `<snapshot>/fs/image/image.boot` (`snapshotter::overlay`), which only exists
//!   because containerd expanded the tar.
//!
//! Publishing the raw bootstrap under a bespoke
//! `application/vnd.oci.image.layer.nydus.bootstrap.v1` media type — as this
//! crate used to — produces an image that no standard nydus deployment can
//! consume: containerd fails the pull with "no processor for media-type".
//!
//! Referrer artifacts are a separate matter: there the bootstrap legitimately
//! travels raw under `MEDIA_TYPE_NYDUS_BOOTSTRAP`, because the snapshotter
//! fetches that blob itself rather than having containerd unpack it.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use registry_client::types::sha256_digest;
use registry_client::{Descriptor, RegistryClient};

/// Path of the bootstrap entry inside the layer tarball. Matches the Go
/// converter's `BootstrapFileNameInLayer`; the snapshotter looks for exactly
/// this path under the unpacked snapshot.
pub const BOOTSTRAP_FILE_NAME_IN_LAYER: &str = "image/image.boot";

/// Ceiling on the *decompressed* size of a bootstrap layer.
///
/// Generous next to any real bootstrap — those scale with inode count and run to
/// tens of megabytes even for very large images — while still refusing a
/// decompression bomb. `registry_client` bounds every HTTP body it buffers;
/// without this the defense would stop at the crate boundary and a hostile image
/// could OOM `nydusify check` / `nydusify mount` with a few kilobytes of gzip.
const MAX_BOOTSTRAP_BYTES: u64 = 1024 * 1024 * 1024;

/// A bootstrap packaged as a gzip'd tar layer.
pub struct BootstrapLayer {
    /// The gzip'd tar bytes — this is what gets pushed as the layer blob.
    pub gzip_bytes: Vec<u8>,
    /// `sha256:…` of [`gzip_bytes`](Self::gzip_bytes); the manifest layer digest.
    pub digest: String,
    /// `sha256:…` of the *uncompressed* tar; the layer's diff id.
    ///
    /// containerd recomputes this while unpacking and rejects the image when it
    /// disagrees with the config's `rootfs.diff_ids`, so it must be the digest of
    /// the tar, never of the gzip stream.
    pub diff_id: String,
}

/// Append one file to the layer tar with fixed ownership and mtime.
///
/// Everything that could vary between two runs of the same conversion is pinned, so the layer
/// digest depends on the content alone -- a converted image has to be reproducible.
fn append_entry(
    builder: &mut tar::Builder<&mut Vec<u8>>,
    name: &str,
    bytes: &[u8],
    what: &str,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, name, bytes)
        .with_context(|| format!("append {what} to the bootstrap layer tar"))
}

/// Package `bootstrap` into a gzip'd tar layer containing `image/image.boot`, plus any
/// `append_files` stored beside it under their base names.
pub fn pack(bootstrap: &Path, append_files: &[PathBuf]) -> Result<BootstrapLayer> {
    let data = std::fs::read(bootstrap)
        .with_context(|| format!("read bootstrap {}", bootstrap.display()))?;

    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        append_entry(
            &mut builder,
            BOOTSTRAP_FILE_NAME_IN_LAYER,
            &data,
            "image/image.boot",
        )?;

        // Extra files ride alongside the bootstrap under their own base names, so a consumer
        // that only pulls this layer can read them without the data blobs. Names are checked
        // for collisions when the conversion is planned, not here.
        for path in append_files {
            let bytes = std::fs::read(path)
                .with_context(|| format!("read --append-in-bootstrap {}", path.display()))?;
            let name = path.file_name().and_then(|n| n.to_str()).with_context(|| {
                format!("--append-in-bootstrap {} has no file name", path.display())
            })?;
            append_entry(&mut builder, name, &bytes, name)?;
        }

        builder
            .into_inner()
            .context("finish the bootstrap layer tar")?;
    }
    let diff_id = sha256_digest(&tar_bytes);

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&tar_bytes)
        .context("gzip the bootstrap layer tar")?;
    let gzip_bytes = encoder.finish().context("finish gzipping the bootstrap")?;
    let digest = sha256_digest(&gzip_bytes);

    Ok(BootstrapLayer {
        gzip_bytes,
        digest,
        diff_id,
    })
}

/// True when `media_type` denotes a tar-based layer, i.e. one whose blob has to
/// be unpacked to get at `image/image.boot`.
///
/// Older images published the bootstrap raw under a bespoke nydus media type;
/// those blobs are already the bootstrap and must not be unpacked.
pub fn is_tar_layer(media_type: &str) -> bool {
    let m = media_type.to_ascii_lowercase();
    m.contains(".tar") || m.ends_with("tar+gzip")
}

/// Extract `image/image.boot` from a bootstrap *layer* blob into `out`.
///
/// Handles both gzip'd and plain tars, so it works whichever compression the
/// publisher chose.
pub fn extract(layer: &Path, out: &Path) -> Result<()> {
    extract_bounded(layer, out, MAX_BOOTSTRAP_BYTES)
}

/// [`extract`] with an explicit decompression ceiling, so the bound itself is
/// testable without materializing a gigabyte.
fn extract_bounded(layer: &Path, out: &Path, max_bytes: u64) -> Result<()> {
    let bytes = std::fs::read(layer)
        .with_context(|| format!("read bootstrap layer {}", layer.display()))?;

    // gzip magic; a plain tar starts with the file name instead.
    let tar_bytes = if bytes.starts_with(&[0x1f, 0x8b]) {
        use std::io::Read as _;
        let mut buf = Vec::new();
        // Bounded on purpose. The layer is registry-supplied, and verifying its
        // digest only proves it is the blob the manifest named — the manifest is
        // written by whoever published the image, so a small blob that inflates
        // to tens of gigabytes is theirs to choose. Read one byte past the
        // ceiling so overshoot is detectable rather than silently truncated.
        flate2::read::GzDecoder::new(bytes.as_slice())
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut buf)
            .context("gunzip bootstrap layer")?;
        if buf.len() as u64 > max_bytes {
            anyhow::bail!(
                "bootstrap layer {} decompresses to more than {} bytes; \
                 refusing to buffer it (a RAFS bootstrap is far smaller)",
                layer.display(),
                max_bytes
            );
        }
        buf
    } else {
        bytes
    };

    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    for entry in archive.entries().context("read bootstrap layer tar")? {
        let mut entry = entry.context("read bootstrap layer tar entry")?;
        let path = entry.path().context("bootstrap layer tar entry path")?;
        if path.as_os_str() == BOOTSTRAP_FILE_NAME_IN_LAYER {
            let mut file =
                std::fs::File::create(out).with_context(|| format!("create {}", out.display()))?;
            std::io::copy(&mut entry, &mut file)
                .with_context(|| format!("extract bootstrap to {}", out.display()))?;
            return Ok(());
        }
    }
    anyhow::bail!(
        "bootstrap layer {} contains no {BOOTSTRAP_FILE_NAME_IN_LAYER} entry",
        layer.display()
    )
}

/// Download a manifest's bootstrap layer and leave the **raw** bootstrap at
/// `<work_dir>/bootstrap`, unpacking it when the layer is a tar.
///
/// Both `check` and `mount` need the bootstrap file itself, not the layer blob:
/// one feeds it to `nydus-image check`, the other to `nydusd`.
pub async fn fetch(
    client: &RegistryClient,
    repo: &str,
    descriptor: &Descriptor,
    work_dir: &Path,
) -> Result<PathBuf> {
    let bootstrap_path = work_dir.join("bootstrap");
    if is_tar_layer(&descriptor.media_type) {
        let layer_path = work_dir.join("bootstrap.layer");
        client
            .get_blob_to_file(repo, &descriptor.digest, &layer_path)
            .await
            .with_context(|| format!("download bootstrap layer {}", descriptor.digest))?;
        extract(&layer_path, &bootstrap_path)
            .context("unpack image/image.boot from the bootstrap layer")?;
    } else {
        // Published by an older build: the blob already is the bootstrap.
        client
            .get_blob_to_file(repo, &descriptor.digest, &bootstrap_path)
            .await
            .with_context(|| format!("download bootstrap {}", descriptor.digest))?;
    }
    Ok(bootstrap_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn write_temp(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[test]
    fn packs_the_bootstrap_at_the_path_the_snapshotter_reads() {
        let (_dir, path) = write_temp(b"RAFS-BOOTSTRAP-BYTES");
        let layer = pack(&path, &[]).unwrap();

        // Round-trip: ungzip, untar, and confirm both the entry path and content.
        let mut tar_bytes = Vec::new();
        flate2::read::GzDecoder::new(layer.gzip_bytes.as_slice())
            .read_to_end(&mut tar_bytes)
            .unwrap();

        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let entries: Vec<(String, Vec<u8>)> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let p = e.path().unwrap().to_string_lossy().into_owned();
                let mut buf = Vec::new();
                e.read_to_end(&mut buf).unwrap();
                (p, buf)
            })
            .collect();

        assert_eq!(entries.len(), 1, "exactly one entry");
        assert_eq!(entries[0].0, BOOTSTRAP_FILE_NAME_IN_LAYER);
        assert_eq!(entries[0].1, b"RAFS-BOOTSTRAP-BYTES");
    }

    /// Ungzip + untar a packed layer into `(entry path, content)` pairs.
    fn entries_of(layer: &BootstrapLayer) -> Vec<(String, Vec<u8>)> {
        let mut tar_bytes = Vec::new();
        flate2::read::GzDecoder::new(layer.gzip_bytes.as_slice())
            .read_to_end(&mut tar_bytes)
            .unwrap();
        tar::Archive::new(tar_bytes.as_slice())
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let p = e.path().unwrap().to_string_lossy().into_owned();
                let mut buf = Vec::new();
                e.read_to_end(&mut buf).unwrap();
                (p, buf)
            })
            .collect()
    }

    #[test]
    fn appended_files_ride_beside_the_bootstrap_under_their_base_names() {
        let (dir, path) = write_temp(b"RAFS-BOOTSTRAP-BYTES");
        let extra = dir.path().join("model-card.json");
        std::fs::write(&extra, br#"{"name":"demo"}"#).unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let deep = nested.join("NOTICE");
        std::fs::write(&deep, b"legal text").unwrap();

        let layer = pack(&path, &[extra, deep]).unwrap();
        let entries = entries_of(&layer);

        assert_eq!(entries.len(), 3);
        // The bootstrap stays first and at its full path; extras are flattened to base names.
        assert_eq!(entries[0].0, BOOTSTRAP_FILE_NAME_IN_LAYER);
        assert_eq!(entries[0].1, b"RAFS-BOOTSTRAP-BYTES");
        assert_eq!(entries[1].0, "model-card.json");
        assert_eq!(entries[1].1, br#"{"name":"demo"}"#);
        assert_eq!(entries[2].0, "NOTICE");
        assert_eq!(entries[2].1, b"legal text");
    }

    #[test]
    fn packing_the_same_inputs_twice_yields_the_same_digest() {
        // Ownership and mtime are pinned so a converted image is reproducible; an appended
        // file's own mtime must not leak into the layer digest.
        let (dir, path) = write_temp(b"bootstrap");
        let extra = dir.path().join("extra.txt");
        std::fs::write(&extra, b"same bytes").unwrap();

        let first = pack(&path, std::slice::from_ref(&extra)).unwrap();
        std::fs::write(&extra, b"same bytes").unwrap();
        let second = pack(&path, std::slice::from_ref(&extra)).unwrap();

        assert_eq!(first.digest, second.digest);
        assert_eq!(first.diff_id, second.diff_id);
    }

    #[test]
    fn extract_still_finds_the_bootstrap_past_appended_entries() {
        // `extract` scans for image/image.boot; appended entries must not shadow it.
        let (dir, path) = write_temp(b"THE-BOOTSTRAP");
        let extra = dir.path().join("sidecar.json");
        std::fs::write(&extra, b"{}").unwrap();
        let layer = pack(&path, &[extra]).unwrap();

        let layer_path = dir.path().join("layer.tar.gz");
        std::fs::write(&layer_path, &layer.gzip_bytes).unwrap();
        let out = dir.path().join("extracted.boot");
        extract(&layer_path, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"THE-BOOTSTRAP");
    }

    #[test]
    fn diff_id_is_the_tar_digest_not_the_gzip_digest() {
        // containerd recomputes the diff id from the uncompressed tar while
        // unpacking; returning the gzip digest here fails the pull with a
        // mismatched-diff-id error.
        let (_dir, path) = write_temp(b"bootstrap");
        let layer = pack(&path, &[]).unwrap();

        assert_ne!(layer.digest, layer.diff_id);
        assert_eq!(layer.digest, sha256_digest(&layer.gzip_bytes));

        let mut tar_bytes = Vec::new();
        flate2::read::GzDecoder::new(layer.gzip_bytes.as_slice())
            .read_to_end(&mut tar_bytes)
            .unwrap();
        assert_eq!(layer.diff_id, sha256_digest(&tar_bytes));
    }

    #[test]
    fn pack_then_extract_round_trips() {
        let (dir, path) = write_temp(b"BOOTSTRAP-CONTENT-42");
        let layer = pack(&path, &[]).unwrap();

        let layer_path = dir.path().join("layer.tar.gz");
        std::fs::write(&layer_path, &layer.gzip_bytes).unwrap();
        let out = dir.path().join("extracted");
        extract(&layer_path, &out).unwrap();

        assert_eq!(std::fs::read(&out).unwrap(), b"BOOTSTRAP-CONTENT-42");
    }

    #[test]
    fn extract_rejects_a_layer_without_the_bootstrap_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let data = b"nope";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_cksum();
            b.append_data(&mut h, "other/file", data.as_slice())
                .unwrap();
            b.into_inner().unwrap();
        }
        let layer_path = dir.path().join("layer.tar");
        std::fs::write(&layer_path, &tar_bytes).unwrap();

        let err = extract(&layer_path, &dir.path().join("out")).unwrap_err();
        assert!(err.to_string().contains(BOOTSTRAP_FILE_NAME_IN_LAYER));
    }

    #[test]
    fn extract_refuses_a_decompression_bomb() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        // 8 MiB of zeros gzips to a few kilobytes: the shape of the attack, at a
        // size a test can afford. The ceiling is passed explicitly so this does
        // not have to reach the real 1 GiB one.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&vec![0u8; 8 * 1024 * 1024]).unwrap();
        let bomb = enc.finish().unwrap();
        assert!(
            bomb.len() < 64 * 1024,
            "fixture should be small on the wire, was {}",
            bomb.len()
        );

        let layer_path = dir.path().join("bomb.tar.gz");
        std::fs::write(&layer_path, &bomb).unwrap();

        let err = extract_bounded(&layer_path, &dir.path().join("out"), 1024 * 1024).unwrap_err();
        assert!(
            err.to_string().contains("decompresses to more than"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn extract_accepts_a_layer_that_fits_the_ceiling() {
        // The bound must not be so eager that it rejects a legitimate layer
        // sitting just under it.
        let (dir, path) = write_temp(b"SMALL-BOOTSTRAP");
        let layer = pack(&path, &[]).unwrap();
        let layer_path = dir.path().join("layer.tar.gz");
        std::fs::write(&layer_path, &layer.gzip_bytes).unwrap();

        let out = dir.path().join("extracted");
        extract_bounded(&layer_path, &out, 64 * 1024).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"SMALL-BOOTSTRAP");
    }

    #[test]
    fn tar_layers_are_distinguished_from_raw_bootstrap_blobs() {
        assert!(is_tar_layer("application/vnd.oci.image.layer.v1.tar+gzip"));
        assert!(is_tar_layer(
            "application/vnd.docker.image.rootfs.diff.tar.gzip"
        ));
        assert!(is_tar_layer("application/vnd.oci.image.layer.v1.tar"));
        // Legacy raw-bootstrap shapes must NOT be unpacked -- the blob already
        // is the bootstrap.
        assert!(!is_tar_layer(
            "application/vnd.oci.image.bootstrap.nydus.v1"
        ));
        assert!(!is_tar_layer(
            "application/vnd.oci.image.layer.nydus.bootstrap.v1"
        ));
    }

    #[test]
    fn packing_is_deterministic() {
        // Same bootstrap in, same layer digest out: a re-convert must not churn
        // the manifest, so the tar header carries no timestamps or ownership.
        let (_d1, p1) = write_temp(b"same-bytes");
        let (_d2, p2) = write_temp(b"same-bytes");

        let a = pack(&p1, &[]).unwrap();
        let b = pack(&p2, &[]).unwrap();

        assert_eq!(a.digest, b.digest);
        assert_eq!(a.diff_id, b.diff_id);
    }
}
