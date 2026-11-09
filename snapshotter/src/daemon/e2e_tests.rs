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

/// Credentials a [`MockRegistry`] requires, the way OCI registries ask for them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegistryAuth {
    /// Anonymous pulls.
    None,
    /// `401` with `WWW-Authenticate: Basic`; blobs need `Authorization: Basic <auth>`.
    Basic,
    /// `401` with a `Bearer realm=…,service=…,scope=…` challenge; the realm hands out
    /// [`E2E_TOKEN`] for `Authorization: Basic <auth>`, and blobs need
    /// `Authorization: Bearer <token>`.
    Bearer,
}

/// The base64 `user:password` the mock registries accept (`e2e-user:e2e-Pa55word-SECRET`).
const E2E_AUTH: &str = "ZTJlLXVzZXI6ZTJlLVBhNTV3b3JkLVNFQ1JFVA==";
/// The password inside [`E2E_AUTH`], which must never reach a log or a file on disk.
const E2E_PASSWORD: &str = "e2e-Pa55word-SECRET";
/// The bearer token the mock realm hands out, which must never reach a log or a file either.
const E2E_TOKEN: &str = "e2e-bearer-TOKEN-7f3a9c";

/// A plain-HTTP OCI registry that serves `GET`/`HEAD /v2/<repo>/blobs/sha256:<id>` from
/// `<dir>/<id>`, honouring `Range`, behind `auth`.
struct MockRegistry {
    addr: String,
    /// Blob requests answered with data.
    served: std::sync::atomic::AtomicUsize,
    /// Blob requests refused with `401`.
    refused: std::sync::atomic::AtomicUsize,
    /// Tokens the realm handed out.
    tokens: std::sync::atomic::AtomicUsize,
}

impl MockRegistry {
    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

/// Start a [`MockRegistry`] on a free local port.
fn serve_registry(dir: PathBuf, auth: RegistryAuth) -> Arc<MockRegistry> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let registry = Arc::new(MockRegistry {
        addr: listener.local_addr().unwrap().to_string(),
        served: Default::default(),
        refused: Default::default(),
        tokens: Default::default(),
    });
    let shared = registry.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (dir, registry) = (dir.clone(), shared.clone());
            std::thread::spawn(move || {
                let _ = serve_registry_request(stream, &dir, auth, &registry);
            });
        }
    });
    registry
}

/// An anonymous [`MockRegistry`]; returns the `host:port` it listens on.
fn serve_blobs(dir: PathBuf) -> String {
    serve_registry(dir, RegistryAuth::None).addr.clone()
}

fn serve_registry_request(
    stream: TcpStream,
    dir: &Path,
    auth: RegistryAuth,
    registry: &MockRegistry,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = stream;
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut range = None;
    let mut authorization = String::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("range") {
                range = Some(value);
            } else if name.eq_ignore_ascii_case("authorization") {
                authorization = value;
            } else if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
        }
    }
    // The token request's form body; read so closing the socket cannot reset the reply.
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    let mut parts = request.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let basic = format!("Basic {E2E_AUTH}");

    if path.starts_with("/token") {
        if authorization != basic {
            return out.write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
        registry.tokens.fetch_add(1, Ordering::SeqCst);
        let token = format!("{{\"token\":\"{E2E_TOKEN}\",\"expires_in\":300}}");
        return out.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{token}",
                token.len()
            )
            .as_bytes(),
        );
    }

    let challenge = match auth {
        RegistryAuth::None => None,
        RegistryAuth::Basic => (authorization != basic).then(|| "Basic realm=\"e2e\"".to_string()),
        RegistryAuth::Bearer => (authorization != format!("Bearer {E2E_TOKEN}")).then(|| {
            let repo = path
                .strip_prefix("/v2/")
                .and_then(|p| p.split_once("/blobs/"))
                .map_or("", |(repo, _)| repo);
            format!(
                "Bearer realm=\"http://{}/token\",service=\"e2e-registry\",\
                 scope=\"repository:{repo}:pull\"",
                registry.addr
            )
        }),
    };
    if let Some(challenge) = challenge {
        registry.refused.fetch_add(1, Ordering::SeqCst);
        return out.write_all(
            format!(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {challenge}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        );
    }

    let file = path
        .rsplit_once("/blobs/sha256:")
        .map(|(_, id)| dir.join(id))
        .filter(|p| p.is_file());
    let Some(file) = file else {
        return out.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    };
    registry.served.fetch_add(1, Ordering::SeqCst);
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
/// through `ensure_instance` with the fanotify driver selected, mounted as EROFS with its
/// data blobs fetched on demand from a registry, and every file reads back with the
/// source bytes.
/// `NYDUS_E2E_ROOT` holds `src/` (the source tree), `bootstrap` and `blobs/<blob id>`.
#[test]
#[ignore = "needs root, Linux >= 6.14 and an ext4 work dir; run misc/fanotify/b4b-referrer-serving-test.sh"]
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
    // A consistent RAFS v6 image pulled from a registry is served by the kernel.
    assert_eq!(mount_fstype_at(&mountpoint).as_deref(), Some("erofs"));
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
            sandbox: true,
        },
        &layers,
    )
    .unwrap_or_else(|e| panic!("convert: {e:#}"));
    // The kernel follows only block addresses, so validate the merged layout before serving it.
    let check = std::process::Command::new(std::env::var("NYDUS_IMAGE").unwrap())
        .args(["check", "-B"])
        .arg(&artifact.bootstrap)
        .arg("--blob-dir")
        .arg(&artifact.backend_dir)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "nydus-image check failed for the merged bootstrap: {}",
        String::from_utf8_lossy(&check.stderr)
    );
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
            true,
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

/// Hand the runtime auth store credentials for `registry` through the handler behind
/// `PUT /api/v1/auth`, the entry point the credential bridge feeds.
fn put_registry_auth(registry: &str) {
    let body = serde_json::json!([{ "registry": registry, "auth": E2E_AUTH }]).to_string();
    assert_eq!(crate::sysctl::handle_auth_put(body.as_bytes()).status, 200);
}

/// A snapshotter config rooted at `root` that pulls over plain HTTP.
fn registry_config(root: &Path) -> SnapshotterConfig {
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
    config
}

/// The mount ID (`/proc/self/mountinfo` field 1) of the top mount at `mountpoint`.
fn mount_id_at(mountpoint: &Path) -> String {
    let target = mountpoint.display().to_string();
    fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .lines()
        .rfind(|line| line.split_whitespace().nth(4) == Some(target.as_str()))
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_else(|| panic!("nothing mounted at {target}"))
        .to_string()
}

/// Read every regular file under `mountpoint`, expecting each read to fail with EIO.
fn assert_every_read_fails_with_eio(mountpoint: &Path) {
    let files = regular_files(mountpoint);
    assert!(!files.is_empty(), "no files under {}", mountpoint.display());
    for rel in files {
        match fs::read(mountpoint.join(&rel)) {
            Ok(data) => panic!(
                "{} read {} bytes without credentials (all zeros: {})",
                rel.display(),
                data.len(),
                data.iter().all(|&b| b == 0)
            ),
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{}: {e}", rel.display()),
        }
    }
}

/// Every file under `dir` (not descending into live mounts) whose bytes contain a secret.
fn files_holding_secrets(dir: &Path) -> Vec<PathBuf> {
    let secrets = [E2E_PASSWORD, E2E_TOKEN, E2E_AUTH];
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() && !is_mounted_at(&path) {
                stack.push(path);
            } else if ft.is_file()
                && let Ok(data) = fs::read(&path)
                && secrets
                    .iter()
                    .any(|s| data.windows(s.len()).any(|w| w == s.as_bytes()))
            {
                found.push(path);
            }
        }
    }
    found
}

fn assert_no_secret_in(what: &str, text: &str) {
    for secret in [E2E_PASSWORD, E2E_TOKEN, E2E_AUTH] {
        assert!(!text.contains(secret), "{what} holds a credential");
    }
}

/// Run the predecessor and successor roles of
/// [`registry_credentials_survive_restart_and_heal`] as child processes, standing in for
/// systemd's fd store and killing the predecessor while its marks are live, the way
/// `fanotify_takeover_serves_uncached_file_data` does. Returns the successor's success, the
/// blob requests `registry` served to it, and both processes' output.
fn run_registry_takeover(
    root: &Path,
    registry: &MockRegistry,
    image_ref: &str,
    with_auth: bool,
) -> (bool, usize, String) {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::net::UnixDatagram;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let notify_path = root.join("notify.sock");
    let _ = fs::remove_file(&notify_path);
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    notify
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    let child = |role: &str| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([REGISTRY_TEST, "--exact", "--ignored", "--nocapture"])
            .env("NYDUS_REG_ROLE", role)
            .env("NYDUS_E2E_ROOT", root)
            .env("NYDUS_REG_ADDR", &registry.addr)
            .env("NYDUS_REG_IMAGE", image_ref)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    };
    let mut predecessor = child("predecessor")
        .env("NOTIFY_SOCKET", &notify_path)
        .spawn()
        .unwrap();
    let (fd_name, group_fd) = loop {
        let mut buf = [0u8; 256];
        let mut fds = [-1; 1];
        let (len, nfds) = match sendfd::RecvWithFd::recv_with_fd(&notify, &mut buf, &mut fds) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            r => r.expect("the predecessor parked no fd"),
        };
        let msg = String::from_utf8_lossy(&buf[..len]).into_owned();
        if nfds == 1 && msg.contains("FDSTORE=1") {
            let name = msg
                .lines()
                .find_map(|l| l.strip_prefix("FDNAME="))
                .unwrap()
                .to_string();
            // SAFETY: `nfds == 1`, so `fds[0]` is a descriptor just received over `SCM_RIGHTS`,
            // owned only by this test, and wrapped exactly once.
            break (name, unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) });
        }
    };
    let mut pred_out = BufReader::new(predecessor.stdout.take().unwrap());
    let mut output = String::new();
    loop {
        let mut line = String::new();
        assert!(
            pred_out.read_line(&mut line).unwrap() > 0,
            "the predecessor never mounted:\n{output}"
        );
        output.push_str(&line);
        if line.contains("PREDECESSOR_READY") {
            break;
        }
    }
    predecessor.kill().unwrap();
    predecessor.wait().unwrap();
    pred_out.read_to_string(&mut output).unwrap();
    predecessor
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();

    let served = registry.served();
    let raw = group_fd.as_raw_fd();
    let mut command = child("successor");
    command
        .env("NYDUS_REG_AUTH", if with_auth { "1" } else { "0" })
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", &fd_name);
    // SAFETY: dup2 is async-signal-safe; it hands the fd over as LISTEN_FDS fd 3.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let successor = command.spawn().unwrap();
    drop(group_fd);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(successor.wait_with_output());
    });
    let result = rx
        .recv_timeout(Duration::from_secs(120))
        .expect("the successor hung for 120s")
        .unwrap();
    output.push_str(&String::from_utf8_lossy(&result.stdout));
    output.push_str(&String::from_utf8_lossy(&result.stderr));
    (result.status.success(), registry.served() - served, output)
}

const REGISTRY_TEST: &str = "daemon::e2e_tests::registry_credentials_survive_restart_and_heal";

/// Registry-backed images on the fanotify path, with credentials the registry demands:
///
/// - **pull**: with Basic credentials from the runtime auth store, the image mounts as EROFS
///   and every file reads back;
/// - **heal**: a fanotify daemon whose handler failed is healed in place and fetches data it
///   never fetched before through the bearer-token flow;
/// - **takeover**: a restarted snapshotter whose auth store was repopulated takes the mount
///   over from the parked group and serves data the predecessor never fetched;
/// - **takeover without credentials**: with an empty auth store the successor still takes
///   over, but every unfetched read fails with EIO (never zeros) and a warning names the
///   image; once credentials arrive through the auth API, the daemon is healed on its own
///   mount and serves every file, while a refresh for a daemon that has credentials heals
///   nothing;
///
/// and no credential reaches a log line or a file on disk. `NYDUS_E2E_ROOT` is an ext4 dir
/// holding `src/` (the source tree), `bootstrap` and `blobs/<blob id>`.
#[test]
#[ignore = "needs root, Linux >= 6.14 and an ext4 work dir; run misc/fanotify/registry-auth-test.sh"]
fn registry_credentials_survive_restart_and_heal() {
    let root = e2e_root();
    let runtime = compio::runtime::Runtime::new().unwrap();
    match std::env::var("NYDUS_REG_ROLE").as_deref() {
        Ok("predecessor") => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("debug")
                .with_writer(std::io::stdout)
                .with_ansi(false)
                .try_init();
            let addr = std::env::var("NYDUS_REG_ADDR").unwrap();
            let image_ref = std::env::var("NYDUS_REG_IMAGE").unwrap();
            put_registry_auth(&addr);
            let supervisor = DaemonSupervisor::new(registry_config(&root.join("takeover")));
            let handle = runtime
                .block_on(supervisor.ensure_instance(
                    &image_ref,
                    &root.join("bootstrap"),
                    "k1",
                    Some(FsDriverType::Fanotify),
                ))
                .unwrap_or_else(|e| panic!("predecessor start: {e:#}"));
            assert_eq!(
                mount_fstype_at(handle.mountpoint()).as_deref(),
                Some("erofs")
            );
            println!("PREDECESSOR_READY {}", handle.mountpoint().display());
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        Ok("successor") => {
            // SAFETY: set before anything else in this process reads the environment.
            unsafe { std::env::set_var("LISTEN_PID", std::process::id().to_string()) };
            let _ = tracing_subscriber::fmt()
                .with_env_filter("debug")
                .with_writer(std::io::stdout)
                .with_ansi(false)
                .try_init();
            if std::env::var("NYDUS_REG_AUTH").as_deref() == Ok("1") {
                // The credential bridge repopulates the store before the takeover.
                put_registry_auth(&std::env::var("NYDUS_REG_ADDR").unwrap());
            }
            let supervisor = Arc::new(DaemonSupervisor::new(registry_config(
                &root.join("takeover"),
            )));
            // As `serve_with_supervisor` does before the auth API serves.
            supervisor.heal_on_auth_updates();
            assert_eq!(runtime.block_on(supervisor.restore_from_store()), 1);
            let image_ref = std::env::var("NYDUS_REG_IMAGE").unwrap();
            let mountpoint = runtime.block_on(supervisor.instances.read())[&image_ref]
                .mountpoint
                .clone();
            let mount_id = mount_id_at(&mountpoint);
            let addr = std::env::var("NYDUS_REG_ADDR").unwrap();
            let heals = || supervisor.auth_heals.load(Ordering::Relaxed);
            if std::env::var("NYDUS_REG_AUTH").as_deref() == Ok("1") {
                assert_same_files(&root.join("src"), &mountpoint);
                println!("SUCCESSOR_READ_OK");
                // Refreshing credentials leaves a daemon that has them alone.
                put_registry_auth(&addr);
                std::thread::sleep(AUTH_HEAL_DEBOUNCE + Duration::from_secs(2));
                assert_eq!(heals(), 0, "a daemon with credentials was healed");
                println!("REFRESH_NO_HEAL_OK");
            } else {
                assert_every_read_fails_with_eio(&mountpoint);
                println!("SUCCESSOR_DENIED_OK");
                // Credentials arriving later heal the daemon on its own mount.
                put_registry_auth(&addr);
                let deadline = Instant::now() + Duration::from_secs(30);
                while heals() == 0 && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
                assert_eq!(heals(), 1, "the daemon was not healed within 30s");
                assert_same_files(&root.join("src"), &mountpoint);
                assert_eq!(
                    mount_id_at(&mountpoint),
                    mount_id,
                    "the image was remounted"
                );
                println!("LATE_AUTH_HEALED_OK heals={}", heals());
            }
            return;
        }
        _ => {}
    }

    let blobs = root.join("blobs");
    let basic = serve_registry(blobs.clone(), RegistryAuth::Basic);
    let bearer = serve_registry(blobs, RegistryAuth::Bearer);

    // Pull: Basic credentials from the auth store.
    put_registry_auth(&basic.addr);
    let supervisor = DaemonSupervisor::new(registry_config(&root.join("pull")));
    let image_ref = format!("{}/e2e/pull:1", basic.addr);
    let handle = runtime
        .block_on(supervisor.ensure_instance(
            &image_ref,
            &root.join("bootstrap"),
            "k1",
            Some(FsDriverType::Fanotify),
        ))
        .unwrap_or_else(|e| panic!("pull start: {e:#}"));
    let mountpoint = handle.mountpoint().to_path_buf();
    assert_eq!(mount_fstype_at(&mountpoint).as_deref(), Some("erofs"));
    assert_same_files(&root.join("src"), &mountpoint);
    assert!(
        basic.refused.load(Ordering::SeqCst) > 0,
        "Basic auth never asked for"
    );
    println!(
        "PULL_OK served={} refused={}",
        basic.served(),
        basic.refused.load(Ordering::SeqCst)
    );
    assert!(basic.served() > 0);
    drop(handle);
    runtime
        .block_on(supervisor.release(&image_ref, "k1"))
        .unwrap();

    // Heal: bearer tokens, fetched again by the healed daemon.
    put_registry_auth(&bearer.addr);
    let supervisor = DaemonSupervisor::new(registry_config(&root.join("heal")));
    let image_ref = format!("{}/e2e/heal:1", bearer.addr);
    let handle = runtime
        .block_on(supervisor.ensure_instance(
            &image_ref,
            &root.join("bootstrap"),
            "k1",
            Some(FsDriverType::Fanotify),
        ))
        .unwrap_or_else(|e| panic!("heal start: {e:#}"));
    let mountpoint = handle.mountpoint().to_path_buf();
    assert_eq!(mount_fstype_at(&mountpoint).as_deref(), Some("erofs"));
    nydus_service::fanotify::inject_panic_on_next_event(&mountpoint);
    let first = regular_files(&root.join("src"))[0].clone();
    let err = fs::read(mountpoint.join(&first)).expect_err("the injected panic was not hit");
    assert_eq!(err.raw_os_error(), Some(libc::EIO), "{err}");
    assert_eq!(handle.state(), DaemonState::UNKNOWN);
    let served = bearer.served();
    let report = runtime.block_on(supervisor.recover()).unwrap();
    assert_eq!(report.restarted, 1, "{report:?}");
    assert_same_files(&root.join("src"), &mountpoint);
    assert!(
        bearer.served() > served,
        "the healed daemon fetched nothing"
    );
    assert!(
        bearer.tokens.load(Ordering::SeqCst) > 0,
        "no bearer token issued"
    );
    println!(
        "HEAL_OK served={} tokens={}",
        bearer.served(),
        bearer.tokens.load(Ordering::SeqCst)
    );
    drop(handle);
    runtime
        .block_on(supervisor.release(&image_ref, "k1"))
        .unwrap();

    // Takeover with the auth store repopulated.
    let image_ref = format!("{}/e2e/takeover:1", bearer.addr);
    let (ok, served, output) = run_registry_takeover(&root, &bearer, &image_ref, true);
    assert!(ok && output.contains("REFRESH_NO_HEAL_OK"), "{output}");
    assert!(served > 0, "the successor fetched nothing");
    assert_no_secret_in("the takeover's logs", &output);
    println!("TAKEOVER_OK served={served}");
    let leftover = registry_config(&root.join("takeover"))
        .snapshotter
        .root
        .join("daemons")
        .join(slug_for(&image_ref))
        .join("mnt");
    let _ = detach_mount_stack(&leftover);

    // Takeover with an empty auth store.
    let image_ref = format!("{}/e2e/noauth:1", bearer.addr);
    let (ok, served, output) = run_registry_takeover(&root, &bearer, &image_ref, false);
    assert!(ok && output.contains("SUCCESSOR_DENIED_OK"), "{output}");
    assert!(output.contains("LATE_AUTH_HEALED_OK"), "{output}");
    assert!(served > 0, "the healed daemon fetched nothing");
    assert!(
        output.lines().any(|l| l.contains("WARN")
            && l.contains("no registry credentials")
            && l.contains(&image_ref)),
        "no warning names the image:\n{output}"
    );
    assert_no_secret_in("the credential-less takeover's logs", &output);
    println!("NOAUTH_TAKEOVER_OK");
    let leftover = registry_config(&root.join("takeover"))
        .snapshotter
        .root
        .join("daemons")
        .join(slug_for(&image_ref))
        .join("mnt");
    let _ = detach_mount_stack(&leftover);

    let leaked = files_holding_secrets(&root);
    assert!(leaked.is_empty(), "credentials on disk: {leaked:#?}");
    println!("NO_SECRETS_ON_DISK_OK");
}
