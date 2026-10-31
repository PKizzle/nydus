// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! `ContentStoreClient` against a real containerd that the test starts itself (temporary root,
//! state and socket), so a system containerd is never touched. Needs root and `containerd` on
//! PATH; run it through misc/containerd-grpc/client-test.sh.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nydus_snapshotter::config::ContainerdConfig;
use nydus_snapshotter::content_store::ContentStoreClient;
use sha2::{Digest, Sha256};

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

struct Containerd {
    child: Child,
    root: PathBuf,
}

impl Containerd {
    fn start(root: &Path) -> Self {
        let socket = root.join("containerd.sock");
        let _ = std::fs::remove_file(&socket);
        let child = Command::new("containerd")
            .arg("--root")
            .arg(root.join("root"))
            .arg("--state")
            .arg(root.join("state"))
            .arg("--address")
            .arg(&socket)
            .arg("--config")
            .arg("/dev/null")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start containerd (is it on PATH, and are we root?)");
        let deadline = Instant::now() + Duration::from_secs(15);
        while !socket.exists() {
            assert!(
                Instant::now() < deadline,
                "containerd socket never appeared"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        Self {
            child,
            root: root.to_path_buf(),
        }
    }

    fn config(&self) -> ContainerdConfig {
        ContainerdConfig {
            address: Some(self.root.join("containerd.sock")),
            namespace: "nydus-test".to_string(),
            content_root: Some(self.root.join("root/io.containerd.content.v1.content")),
        }
    }

    fn stop(mut self) {
        self.kill();
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Containerd {
    fn drop(&mut self) {
        self.kill();
    }
}

fn labels() -> HashMap<String, String> {
    HashMap::from([("nydus.test/role".to_string(), "fixture".to_string())])
}

fn digest_of(bytes: &[u8]) -> String {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

#[test]
#[ignore = "needs root and containerd; run misc/containerd-grpc/client-test.sh"]
fn content_and_images_round_trip_and_survive_a_containerd_restart() {
    let dir = tempfile::tempdir().unwrap();
    let containerd = Containerd::start(dir.path());
    let client = ContentStoreClient::new(&containerd.config()).unwrap();
    let small = b"hello containerd";

    compio::runtime::Runtime::new().unwrap().block_on(async {
        // Small blob: write, info with labels, read back.
        let digest = client.write_bytes(small, "small", labels()).await.unwrap();
        assert_eq!(digest, digest_of(small));
        let info = client.info(&digest).await.unwrap().expect("blob present");
        assert_eq!(info.size, small.len() as u64);
        assert_eq!(info.labels["nydus.test/role"], "fixture");
        assert_eq!(client.fetch_bytes(&digest).await.unwrap(), small);

        // Larger than tonic's 4 MiB default frame: exercises the raised encoding limit and a
        // multi-chunk Read stream.
        let big: Vec<u8> = (0..6 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let big_path = dir.path().join("big.bin");
        std::fs::write(&big_path, &big).unwrap();
        let big_digest = client.write_blob(&big_path, labels()).await.unwrap();
        assert_eq!(big_digest, digest_of(&big));
        assert_eq!(client.fetch_bytes(&big_digest).await.unwrap(), big);

        // Image records: create, get, list, upsert to a new target, delete.
        let name = "nydus.test/image:1";
        client
            .images_create(name, &digest, small.len() as u64, OCI_MANIFEST, labels())
            .await
            .unwrap();
        let image = client
            .images_get(name)
            .await
            .unwrap()
            .expect("image present");
        assert_eq!(image.digest, digest);
        let listed = client.images_list().await.unwrap();
        assert!(
            listed
                .iter()
                .any(|r| r.name == name && r.target_digest == digest)
        );
        client
            .images_upsert(name, &big_digest, big.len() as u64, OCI_MANIFEST, labels())
            .await
            .unwrap();
        let image = client
            .images_get(name)
            .await
            .unwrap()
            .expect("image present");
        assert_eq!(image.digest, big_digest);
        client.images_delete(name).await.unwrap();
        assert!(client.images_get(name).await.unwrap().is_none());

        // An absent digest is NotFound, not an error.
        let absent = format!("sha256:{}", "0".repeat(64));
        assert!(client.info(&absent).await.unwrap().is_none());

        // Root the small blob with an image record so containerd's GC keeps it across the
        // restart below; unreferenced content is collected when containerd starts.
        client
            .images_create(
                "nydus.test/keep:1",
                &digest,
                small.len() as u64,
                OCI_MANIFEST,
                labels(),
            )
            .await
            .unwrap();
    });

    // Restart containerd: the cached connection dies, and the next call must reach the new
    // containerd through a fresh one.
    containerd.stop();
    let containerd = Containerd::start(dir.path());
    compio::runtime::Runtime::new().unwrap().block_on(async {
        let info = client.info(&digest_of(small)).await.unwrap();
        assert!(info.is_some(), "blob survives the restart and is reachable");
    });

    // Stopped containerd: a prompt connection error, not a hang.
    containerd.stop();
    compio::runtime::Runtime::new().unwrap().block_on(async {
        let started = Instant::now();
        let err = client.info(&digest_of(small)).await.unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "call against a stopped containerd hung: {err:#}"
        );
    });
}
