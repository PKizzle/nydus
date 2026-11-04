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
use nydus_snapshotter::containerd_api::services::leases::v1::{
    CreateRequest, DeleteRequest, ListRequest, leases_client::LeasesClient,
};
use nydus_snapshotter::containerd_grpc::ContainerdChannel;
use nydus_snapshotter::content_store::{ContentStoreClient, is_containerd_unavailable};
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
            hosts_dir: None,
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

/// Delete lease `id` and wait for the GC pass that deletion triggers (`sync`).
async fn delete_lease_and_collect(channel: &ContainerdChannel, id: &str) {
    LeasesClient::new(channel.clone())
        .delete(DeleteRequest {
            id: id.to_string(),
            sync: true,
        })
        .await
        .unwrap();
}

/// Run one GC pass to completion, through a throwaway lease.
async fn collect_garbage(channel: &ContainerdChannel) {
    LeasesClient::new(channel.clone())
        .create(CreateRequest {
            id: "nydus-test-gc".to_string(),
            labels: HashMap::new(),
        })
        .await
        .unwrap();
    delete_lease_and_collect(channel, "nydus-test-gc").await;
}

async fn lease_ids(channel: &ContainerdChannel) -> Vec<String> {
    LeasesClient::new(channel.clone())
        .list(ListRequest { filters: vec![] })
        .await
        .unwrap()
        .into_inner()
        .leases
        .into_iter()
        .map(|lease| lease.id)
        .collect()
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
        let lease = client.create_lease("test").await.unwrap();
        // Small blob: write, info with labels, read back.
        let digest = client
            .write_bytes(small, "small", labels(), &lease)
            .await
            .unwrap();
        assert_eq!(digest, digest_of(small));
        let info = client.info(&digest).await.unwrap().expect("blob present");
        assert_eq!(info.size, small.len() as u64);
        assert_eq!(info.labels["nydus.test/role"], "fixture");
        assert_eq!(client.fetch_bytes(&digest).await.unwrap(), small);
        // containerd's startup GC runs 100 ms after it starts and collects committed content
        // nothing references; the upload's lease must keep the blob through it.
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            client.info(&digest).await.unwrap().is_some(),
            "unreferenced blob survives a GC pass"
        );

        // Root the small blob with its own image record right away. The image-record checks
        // below repoint and delete another record, and containerd's GC (triggered by deletes
        // and run again at startup) collects content nothing references.
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

        // Larger than tonic's 4 MiB default frame: exercises the raised encoding limit and a
        // multi-chunk Read stream.
        let big: Vec<u8> = (0..6 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let big_path = dir.path().join("big.bin");
        std::fs::write(&big_path, &big).unwrap();
        let big_digest = client
            .write_blob(&big_path, labels(), &lease)
            .await
            .unwrap();
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
        assert!(
            is_containerd_unavailable(&err),
            "a stopped containerd reads as unavailable: {err:#}"
        );
    });
}

/// The upload protocol of auto-zran: every blob goes in under one lease, which keeps it from
/// GC until the Image record roots it, and is deleted afterwards. A blob that is already
/// present (left by an earlier, failed upload) is taken into the new lease rather than
/// trusted to survive on its own.
#[test]
#[ignore = "needs root and containerd; run misc/containerd-grpc/client-test.sh"]
fn an_upload_lease_holds_content_until_the_image_record_roots_it() {
    let dir = tempfile::tempdir().unwrap();
    let containerd = Containerd::start(dir.path());
    let config = containerd.config();
    let client = ContentStoreClient::new(&config).unwrap();
    let channel = ContainerdChannel::new(config.address(), &config.namespace);
    let leftover = b"left behind by a failed upload";
    let manifest = b"sidecar manifest";
    let name = "nydus.test/sidecar:1";

    compio::runtime::Runtime::new().unwrap().block_on(async {
        // Let containerd's startup GC pass (100 ms after start) go by; the passes below are
        // the test's own.
        compio::time::sleep(Duration::from_millis(500)).await;

        let failed_upload = client.create_lease("test-upload").await.unwrap();
        let leftover_digest = client
            .write_bytes(leftover, "leftover", labels(), &failed_upload)
            .await
            .unwrap();

        let upload = client.create_lease("test-upload").await.unwrap();
        let again = client
            .write_bytes(leftover, "leftover", labels(), &upload)
            .await
            .unwrap();
        assert_eq!(again, leftover_digest);
        let manifest_digest = client
            .write_bytes(manifest, "manifest", labels(), &upload)
            .await
            .unwrap();

        // The failed upload's lease goes, with a GC pass: the leftover blob now has only the
        // new upload's lease, and that must be enough.
        delete_lease_and_collect(&channel, &failed_upload).await;
        assert!(client.info(&leftover_digest).await.unwrap().is_some());
        assert!(client.info(&manifest_digest).await.unwrap().is_some());
        collect_garbage(&channel).await;
        assert!(
            client.info(&manifest_digest).await.unwrap().is_some(),
            "content under a live lease survives GC until the image record exists"
        );

        client
            .images_upsert(
                name,
                &manifest_digest,
                manifest.len() as u64,
                OCI_MANIFEST,
                labels(),
            )
            .await
            .unwrap();
        client.delete_lease(&upload).await.unwrap();
        assert!(
            !lease_ids(&channel).await.contains(&upload),
            "the upload lease is gone after success"
        );
        // Deleting it again (an already expired lease) is not an error.
        client.delete_lease(&upload).await.unwrap();

        collect_garbage(&channel).await;
        assert!(
            client.info(&manifest_digest).await.unwrap().is_some(),
            "the image record roots the manifest once the lease is gone"
        );
        assert!(
            client.info(&leftover_digest).await.unwrap().is_none(),
            "nothing but the deleted lease held the leftover blob"
        );

        // Two uploads of one blob racing each other: one commits, the other finds it
        // committed (AlreadyExists, or present already) and both succeed.
        let lease = client.create_lease("test-race").await.unwrap();
        let shared: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i % 253) as u8).collect();
        let (a, b) = futures::join!(
            client.write_bytes(&shared, "race-a", labels(), &lease),
            client.write_bytes(&shared, "race-b", labels(), &lease)
        );
        assert_eq!(a.unwrap(), digest_of(&shared));
        assert_eq!(b.unwrap(), digest_of(&shared));
        assert_eq!(
            client.fetch_bytes(&digest_of(&shared)).await.unwrap(),
            shared
        );
    });
}
