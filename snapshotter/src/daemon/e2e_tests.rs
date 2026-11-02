// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Root-only tests of the production mount paths: each starts its daemon the way
//! the gRPC `Prepare`/`Mounts` handlers do and reads file data back through the
//! kernel mount. The `misc/fanotify/*.sh` scripts build their inputs and run them.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};

use sha2::{Digest, Sha256};

use super::*;
use crate::auto_accel_sidecar::SidecarLocator;
use crate::auto_zran::{
    AUTO_ACCEL_MANIFEST_VERSION, AutoAccelDescriptor, AutoAccelLayerDescriptor, AutoAccelManifest,
    OciConfigRootfs,
};
use crate::config::{ContainerdConfig, PeerMirrorConfig, RegistryBackendConfig};
use crate::content_store::ContentStoreClient;
use crate::local_accel::{self, LocalAccelConfig, SchedClass, SourceLayer};

fn e2e_root() -> PathBuf {
    PathBuf::from(std::env::var("NYDUS_E2E_ROOT").expect("NYDUS_E2E_ROOT unset"))
}

fn file_sha256(path: &Path) -> String {
    hex::encode(Sha256::digest(fs::read(path).unwrap()))
}

/// Relative paths of every regular file under `dir`.
fn regular_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let ft = entry.file_type().unwrap();
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                files.push(entry.path().strip_prefix(dir).unwrap().to_path_buf());
            }
        }
    }
    files
}

/// Assert the mount holds exactly the regular files of `expected`, with the same bytes.
/// Files are read in reverse path order, so the last member of a layer is read before
/// the ones behind it.
fn assert_same_files(expected: &Path, mountpoint: &Path) {
    let mut want = regular_files(expected);
    want.sort();
    want.reverse();
    assert!(!want.is_empty(), "no files under {}", expected.display());
    let mut got = regular_files(mountpoint);
    got.sort();
    got.reverse();
    assert_eq!(got, want, "file list of {}", mountpoint.display());
    for rel in &want {
        let data = fs::read(mountpoint.join(rel))
            .unwrap_or_else(|e| panic!("read {}: {e}", rel.display()));
        assert!(
            data == fs::read(expected.join(rel)).unwrap(),
            "content of {} differs from the source",
            rel.display()
        );
    }
}

/// A plain-HTTP OCI registry that serves `GET`/`HEAD /v2/<repo>/blobs/sha256:<id>`
/// from `<dir>/<id>`, honouring `Range`. Returns the `host:port` it listens on.
fn serve_blobs(dir: PathBuf) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let dir = dir.clone();
            std::thread::spawn(move || {
                let _ = serve_blob_request(stream, &dir);
            });
        }
    });
    addr
}

fn serve_blob_request(stream: TcpStream, dir: &Path) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = stream;
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut range = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("range")
        {
            range = Some(value.trim().to_string());
        }
    }
    let mut parts = request.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let file = path
        .rsplit_once("/blobs/sha256:")
        .map(|(_, id)| dir.join(id))
        .filter(|p| p.is_file());
    let Some(file) = file else {
        return out.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    };
    let size = fs::metadata(&file)?.len();
    let (status, start, end) = match range.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
        Some(r) => {
            let (a, b) = r.split_once('-').unwrap();
            let start: u64 = a.parse().unwrap();
            let end = if b.is_empty() {
                size - 1
            } else {
                b.parse::<u64>().unwrap().min(size - 1)
            };
            ("206 Partial Content", start, end)
        }
        None => ("200 OK", 0, size - 1),
    };
    let len = end + 1 - start;
    let mut head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {len}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n"
    );
    if status.starts_with("206") {
        head.push_str(&format!("Content-Range: bytes {start}-{end}/{size}\r\n"));
    }
    head.push_str("\r\n");
    out.write_all(head.as_bytes())?;
    if method != "HEAD" {
        let mut f = fs::File::open(&file)?;
        f.seek(SeekFrom::Start(start))?;
        std::io::copy(&mut f.take(len), &mut out)?;
    }
    out.flush()
}

/// The referrer path: an image whose bootstrap came from a referrer artifact is served
/// through `ensure_instance` with the fanotify driver selected, its data blobs fetched
/// from a registry, and every file reads back with the source bytes.
/// `NYDUS_E2E_ROOT` holds `src/` (the source tree), `bootstrap` and `blobs/<blob id>`.
#[test]
#[ignore = "needs root and FUSE; run misc/fanotify/b4b-referrer-serving-test.sh"]
fn referrer_daemon_serves_every_file() {
    let root = e2e_root();
    let registry = serve_blobs(root.join("blobs"));
    let mut config = SnapshotterConfig::default();
    config.snapshotter.root = root.join("snapshotter");
    config.snapshotter.cache.work_dir = root.join("cache");
    config.backends.registry = Some(RegistryBackendConfig {
        mirrors: Vec::new(),
        skip_verify: false,
        ca_cert_files: Vec::new(),
        plain_http: true,
        request_timeout: "10s".to_string(),
    });
    let supervisor = DaemonSupervisor::new(config);
    let runtime = compio::runtime::Runtime::new().unwrap();
    let image_ref = format!("{registry}/b4b/app:1");

    let handle = runtime
        .block_on(supervisor.ensure_instance(
            &image_ref,
            &root.join("bootstrap"),
            "k1",
            Some(FsDriverType::Fanotify),
        ))
        .unwrap_or_else(|e| panic!("referrer daemon start: {e:#}"));
    let mountpoint = handle.mountpoint().to_path_buf();
    println!(
        "referrer image mounted as {:?} at {}",
        mount_fstype_at(&mountpoint),
        mountpoint.display()
    );
    assert_same_files(&root.join("src"), &mountpoint);

    drop(handle);
    runtime
        .block_on(supervisor.release(&image_ref, "k1"))
        .unwrap();
    assert!(
        !is_mounted_at(&mountpoint),
        "mount outlived its released daemon"
    );
}

/// The auto-accel path from conversion to data: `local_accel::convert` builds the
/// artifact, its blobs go into a content store the way the auto-zran worker uploads
/// them, `SidecarLocator::stage` lays out the backend dir from there, and the daemon
/// `ensure_instance_local` starts serves every file over fanotify/EROFS.
/// `NYDUS_E2E_ROOT` holds `layers/` (layer blobs, applied in file-name order) and
/// `expected/` (the merged tree); `NYDUS_IMAGE` is the `nydus-image` binary.
#[test]
#[ignore = "needs root, Linux >= 6.14 and an ext4 work dir; run misc/fanotify/ref-layer-formats-test.sh"]
fn auto_accel_sidecar_serves_converted_layers() {
    let root = e2e_root();
    let content_root = root.join("content");
    let blobs = content_root.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    // Store a blob under its sha256, as containerd's content store does.
    let store = |path: &Path| -> AutoAccelDescriptor {
        let digest = file_sha256(path);
        fs::copy(path, blobs.join(&digest)).unwrap();
        AutoAccelDescriptor {
            digest: format!("sha256:{digest}"),
            size: fs::metadata(path).unwrap().len(),
        }
    };

    let mut layer_files: Vec<PathBuf> = fs::read_dir(root.join("layers"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    layer_files.sort();
    let layers: Vec<SourceLayer> = layer_files
        .iter()
        .map(|path| {
            let digest = store(path).digest;
            SourceLayer {
                path: content_root.join("blobs/sha256").join(&digest[7..]),
                digest,
            }
        })
        .collect();

    let artifact = local_accel::convert(
        &LocalAccelConfig {
            nydus_image: PathBuf::from(std::env::var("NYDUS_IMAGE").expect("NYDUS_IMAGE unset")),
            work_dir: root.join("convert"),
            sched: SchedClass::Normal,
            nice: 0,
        },
        &layers,
    )
    .unwrap_or_else(|e| panic!("convert: {e:#}"));
    let zran_indexes = artifact
        .zran_index_blob_ids
        .iter()
        .zip(&layers)
        .filter_map(|(id, layer)| {
            let index = store(&artifact.backend_dir.join(id.as_ref()?));
            Some(AutoAccelLayerDescriptor {
                layer_digest: layer.digest.clone(),
                digest: index.digest,
                size: index.size,
            })
        })
        .collect();
    let subject = format!("sha256:{}", "e2e0".repeat(16));
    let manifest = AutoAccelManifest {
        version: AUTO_ACCEL_MANIFEST_VERSION,
        subject_manifest_digest: subject.clone(),
        image_ref: "e2e.invalid/formats/app:1".to_string(),
        bootstrap: store(&artifact.bootstrap),
        zran_indexes,
        prefetch_blob: None,
        architecture: "amd64".to_string(),
        os: "linux".to_string(),
        rootfs: OciConfigRootfs {
            kind: "layers".to_string(),
            diff_ids: Vec::new(),
        },
    };

    let snapshotter_root = root.join("snapshotter");
    let content_store = ContentStoreClient::new(&ContainerdConfig {
        content_root: Some(content_root.clone()),
        ..ContainerdConfig::default()
    })
    .unwrap();
    let locator = SidecarLocator::new(
        content_store,
        &snapshotter_root,
        &PeerMirrorConfig::default(),
    );
    let runtime = compio::runtime::Runtime::new().unwrap();
    let staged = runtime
        .block_on(locator.stage(&subject, &manifest))
        .unwrap_or_else(|e| panic!("stage: {e:#}"));

    let mut config = SnapshotterConfig::default();
    config.snapshotter.root = snapshotter_root;
    let supervisor = DaemonSupervisor::new(config);
    let handle = runtime
        .block_on(supervisor.ensure_instance_local(
            &manifest.image_ref,
            &staged.bootstrap,
            &staged.backend_dir,
            "k1",
        ))
        .unwrap_or_else(|e| panic!("auto-accel daemon start: {e:#}"));
    let mountpoint = handle.mountpoint().to_path_buf();
    assert_eq!(mount_fstype_at(&mountpoint).as_deref(), Some("erofs"));
    assert_same_files(&root.join("expected"), &mountpoint);

    drop(handle);
    runtime
        .block_on(supervisor.release(&manifest.image_ref, "k1"))
        .unwrap();
    assert!(
        !is_mounted_at(&mountpoint),
        "mount outlived its released daemon"
    );
}
