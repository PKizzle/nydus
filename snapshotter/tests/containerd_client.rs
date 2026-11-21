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

use nydus_snapshotter::auto_zran::completeness_check;
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
        // CRI and NRI are not needed, and NRI binds the fixed /var/run/nri/nri.sock, so tests
        // running in parallel would race for it.
        let config = root.join("config.toml");
        std::fs::write(
            &config,
            "disabled_plugins = [\"io.containerd.grpc.v1.cri\", \"io.containerd.nri.v1.nri\"]\n",
        )
        .expect("containerd config");
        let child = Command::new("containerd")
            .arg("--root")
            .arg(root.join("root"))
            .arg("--state")
            .arg(root.join("state"))
            .arg("--address")
            .arg(&socket)
            .arg("--config")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(root.join("containerd.log")).expect("containerd log"))
            .spawn()
            .expect("start containerd (is it on PATH, and are we root?)");
        let mut this = Self {
            child,
            root: root.to_path_buf(),
        };
        // containerd 2.x creates the socket before it accepts on it: wait for a connection.
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            let log = || std::fs::read_to_string(root.join("containerd.log")).unwrap_or_default();
            if let Ok(Some(status)) = this.child.try_wait() {
                panic!("containerd exited ({status}):\n{}", log());
            }
            assert!(
                Instant::now() < deadline,
                "containerd never accepted on its socket:\n{}",
                log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        this
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

/// Major version of the `containerd` on PATH.
fn containerd_major() -> u32 {
    let out = Command::new("containerd")
        .arg("--version")
        .output()
        .unwrap();
    // "containerd <source> v1.6.20 <commit>" or "... 2.0.4 ..."
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find_map(|w| w.trim_start_matches('v').split('.').next()?.parse().ok())
        .expect("containerd --version names a version")
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
        let upload = client.begin_upload("test").await.unwrap();
        // Small blob: write, info with labels, read back.
        let digest = upload.write_bytes(small, "small", labels()).await.unwrap();
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
        let big_digest = upload.write_blob(&big_path, labels()).await.unwrap();
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
        client.images_delete(name, None).await.unwrap();
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

        let failed_upload = client.begin_upload("test-upload").await.unwrap();
        let leftover_digest = failed_upload
            .write_bytes(leftover, "leftover", labels())
            .await
            .unwrap();

        let upload = client.begin_upload("test-upload").await.unwrap();
        let upload_lease = upload.lease().to_string();
        let again = upload
            .write_bytes(leftover, "leftover", labels())
            .await
            .unwrap();
        assert_eq!(again, leftover_digest);
        let manifest_digest = upload
            .write_bytes(manifest, "manifest", labels())
            .await
            .unwrap();

        // The failed upload's lease goes, with a GC pass: the leftover blob now has only the
        // new upload's lease, and that must be enough.
        delete_lease_and_collect(&channel, failed_upload.lease()).await;
        assert!(client.info(&leftover_digest).await.unwrap().is_some());
        assert!(client.info(&manifest_digest).await.unwrap().is_some());
        collect_garbage(&channel).await;
        assert!(
            client.info(&manifest_digest).await.unwrap().is_some(),
            "content under a live lease survives GC until the image record exists"
        );

        upload
            .finish_upsert(
                name,
                &manifest_digest,
                manifest.len() as u64,
                OCI_MANIFEST,
                labels(),
            )
            .await
            .unwrap();
        assert!(
            !lease_ids(&channel).await.contains(&upload_lease),
            "the upload lease is gone after success"
        );

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
        let race = client.begin_upload("test-race").await.unwrap();
        let shared: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i % 253) as u8).collect();
        let (a, b) = futures::join!(
            race.write_bytes(&shared, "race-a", labels()),
            race.write_bytes(&shared, "race-b", labels())
        );
        assert_eq!(a.unwrap(), digest_of(&shared));
        assert_eq!(b.unwrap(), digest_of(&shared));
        assert_eq!(
            client.fetch_bytes(&digest_of(&shared)).await.unwrap(),
            shared
        );

        // finish_create never overwrites a record. One that already points at another
        // manifest does not root this upload, so its lease stays and finishing fails.
        let other = client.begin_upload("test-conflict").await.unwrap();
        let other_lease = other.lease().to_string();
        let other_manifest = b"another sidecar manifest";
        let other_digest = other
            .write_bytes(other_manifest, "other", labels())
            .await
            .unwrap();
        let err = other
            .finish_create(
                name,
                &other_digest,
                other_manifest.len() as u64,
                OCI_MANIFEST,
                labels(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains(&manifest_digest), "{err:#}");
        assert!(
            lease_ids(&channel).await.contains(&other_lease),
            "a lease whose blobs no record roots is kept"
        );
        assert_eq!(
            client.images_get(name).await.unwrap().unwrap().digest,
            manifest_digest
        );

        // A record that already points at this upload's manifest roots it: the lease goes.
        let same = client.begin_upload("test-same").await.unwrap();
        let same_lease = same.lease().to_string();
        same.write_bytes(manifest, "manifest", labels())
            .await
            .unwrap();
        same.finish_create(
            name,
            &manifest_digest,
            manifest.len() as u64,
            OCI_MANIFEST,
            labels(),
        )
        .await
        .unwrap();
        assert!(!lease_ids(&channel).await.contains(&same_lease));
    });
}

#[test]
#[ignore = "needs root and containerd; run misc/containerd-grpc/client-test.sh"]
fn incomplete_sidecars_are_detected_and_deletes_honour_the_listed_target() {
    let dir = tempfile::tempdir().unwrap();
    let containerd = Containerd::start(dir.path());
    let client = ContentStoreClient::new(&containerd.config()).unwrap();
    let missing = digest_of(b"never written");

    compio::runtime::Runtime::new().unwrap().block_on(async {
        let upload = client.begin_upload("test-sidecar").await.unwrap();
        let config = upload.write_bytes(b"{}", "config", labels()).await.unwrap();
        let layer = upload
            .write_bytes(b"bootstrap", "layer", labels())
            .await
            .unwrap();
        let manifest_naming = |layers: &[&str]| {
            serde_json::json!({
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST,
                "config": {"mediaType": "application/json", "digest": config, "size": 2},
                "layers": layers.iter().map(|d| serde_json::json!(
                    {"mediaType": "application/octet-stream", "digest": d, "size": 9}
                )).collect::<Vec<_>>(),
            })
            .to_string()
            .into_bytes()
        };
        let complete = manifest_naming(&[&layer]);
        let incomplete = manifest_naming(&[&layer, &missing]);
        let complete_digest = upload
            .write_bytes(&complete, "complete", labels())
            .await
            .unwrap();
        let incomplete_digest = upload
            .write_bytes(&incomplete, "incomplete", labels())
            .await
            .unwrap();

        let check = |digest: String| {
            let client = client.clone();
            async move { completeness_check(&client, &digest).await.unwrap() }
        };
        assert!(check(complete_digest.clone()).await);
        assert!(
            !check(incomplete_digest.clone()).await,
            "a named blob is missing"
        );
        assert!(
            !check(missing.clone()).await,
            "the manifest itself is missing"
        );

        let name = "nydus.test/sidecar:target";
        upload
            .finish_upsert(
                name,
                &complete_digest,
                complete.len() as u64,
                OCI_MANIFEST,
                labels(),
            )
            .await
            .unwrap();
        client
            .images_delete(name, Some(&incomplete_digest))
            .await
            .unwrap();
        // containerd 2.0 added the conditional delete; older ones ignore the target.
        assert_eq!(
            client.images_get(name).await.unwrap().is_some(),
            containerd_major() >= 2,
            "a record pointing elsewhere than the listed target is kept (containerd 2.0+)"
        );
        client
            .images_delete(name, Some(&complete_digest))
            .await
            .unwrap();
        assert!(client.images_get(name).await.unwrap().is_none());
    });
    containerd.stop();
}

/// A lookup that arrives while another lookup's refresh is in flight does not take that
/// refresh's answer: its listing may predate an image created since. The first lookup is held
/// in its walk of a large image config while a second image is created and a second lookup
/// arrives, which must name the second image.
#[test]
#[ignore = "needs root and containerd; run misc/containerd-grpc/client-test.sh"]
fn a_lookup_never_answers_from_a_listing_older_than_itself() {
    use nydus_snapshotter::containerd_lookup::{Claim, Claimant, ClaimedImage, ContainerdLookup};

    let dir = tempfile::tempdir().unwrap();
    let containerd = Containerd::start(dir.path());
    let namespace = containerd.config().namespace;
    let client = ContentStoreClient::new(&containerd.config()).unwrap();
    let lookup = ContainerdLookup::new(client.clone());

    compio::runtime::Runtime::new().unwrap().block_on(async {
        // Both images claim one chain. The first one's config is large, so walking it keeps
        // the first lookup's refresh in flight long after its listing was taken.
        let diff_id = digest_of(b"layer");
        let upload = client.begin_upload("test").await.unwrap();
        let mut manifests = Vec::new();
        for (i, padding) in [64 << 20, 0].into_iter().enumerate() {
            let config = serde_json::json!({
                "architecture": "amd64", "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": [diff_id]},
                "padding": "x".repeat(padding),
            })
            .to_string();
            let config_digest = upload
                .write_bytes(config.as_bytes(), &format!("config-{i}"), labels())
                .await
                .unwrap();
            let manifest = serde_json::json!({
                "schemaVersion": 2, "mediaType": OCI_MANIFEST,
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                           "digest": config_digest, "size": config.len()},
                "layers": [],
            })
            .to_string();
            let digest = upload
                .write_bytes(manifest.as_bytes(), &format!("manifest-{i}"), labels())
                .await
                .unwrap();
            manifests.push((digest, manifest.len() as u64));
        }
        let (slow, slow_size) = &manifests[0];
        let (late, late_size) = &manifests[1];
        client
            .images_create(
                "nydus.test/slow:1",
                slow,
                *slow_size,
                OCI_MANIFEST,
                labels(),
            )
            .await
            .unwrap();

        let first = lookup.lookup(&namespace, &diff_id);
        let second = async {
            compio::time::sleep(Duration::from_millis(5)).await;
            client
                .images_create(
                    "nydus.test/late:1",
                    late,
                    *late_size,
                    OCI_MANIFEST,
                    labels(),
                )
                .await
                .unwrap();
            lookup.lookup(&namespace, &diff_id).await.unwrap()
        };
        let (first, second) = futures::future::join(first, second).await;
        assert_eq!(
            first.unwrap(),
            Claim::One(Claimant {
                repository: "nydus.test/slow".to_string(),
                images: vec![ClaimedImage {
                    image_ref: "nydus.test/slow:1".to_string(),
                    target: slow.clone(),
                }],
            })
        );
        assert_eq!(
            second,
            Claim::Ambiguous(vec![
                "nydus.test/late".to_string(),
                "nydus.test/slow".to_string()
            ])
        );
    });
}

/// containerd's Go decoder lets a later duplicate key win, so an image whose manifest repeats
/// `layers` and whose config repeats `rootfs` is a usable image claiming the chain of its last
/// `rootfs`. The lookup reads it the same way, and JSON containerd cannot parse either claims
/// nothing, so neither makes another repository's claim uncertain.
#[test]
#[ignore = "needs root and containerd; run misc/containerd-grpc/client-test.sh"]
fn image_json_is_read_as_containerd_reads_it() {
    use nydus_snapshotter::containerd_lookup::{Claim, ContainerdLookup};

    let dir = tempfile::tempdir().unwrap();
    let containerd = Containerd::start(dir.path());
    let namespace = containerd.config().namespace;
    let client = ContentStoreClient::new(&containerd.config()).unwrap();
    let lookup = ContainerdLookup::new(client.clone());

    compio::runtime::Runtime::new().unwrap().block_on(async {
        let (first, last, app) = (digest_of(b"first"), digest_of(b"last"), digest_of(b"app"));
        let upload = client.begin_upload("test").await.unwrap();
        let image = async |name: &str, config: String, layers: &str| {
            let config_digest = upload
                .write_bytes(config.as_bytes(), &format!("config-{name}"), labels())
                .await
                .unwrap();
            let manifest = format!(
                r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},{layers}}}"#,
                config.len()
            );
            let digest = upload
                .write_bytes(manifest.as_bytes(), &format!("manifest-{name}"), labels())
                .await
                .unwrap();
            client
                .images_create(name, &digest, manifest.len() as u64, OCI_MANIFEST, labels())
                .await
                .unwrap();
        };
        let rootfs = |diff_id: &str| format!(r#""rootfs":{{"type":"layers","diff_ids":["{diff_id}"]}}"#);
        image(
            "nydus.test/app:1",
            format!(r#"{{"architecture":"amd64","os":"linux",{}}}"#, rootfs(&app)),
            r#""layers":[]"#,
        )
        .await;
        image(
            "nydus.test/dup:1",
            format!(
                r#"{{"architecture":"amd64","os":"linux",{},{}}}"#,
                rootfs(&first),
                rootfs(&last)
            ),
            r#""layers":[{"digest":"sha256:00"}],"layers":[]"#,
        )
        .await;
        image(
            "nydus.test/broken:1",
            r#"{"architecture":"amd64","os":"linux","rootfs":"#.to_string(),
            r#""layers":[]"#,
        )
        .await;

        let claimant = |claim: Claim| match claim {
            Claim::One(claimant) => claimant.repository,
            other => panic!("expected one claimant, got {other:?}"),
        };
        assert_eq!(
            claimant(lookup.lookup(&namespace, &app).await.unwrap()),
            "nydus.test/app"
        );
        assert_eq!(
            claimant(lookup.lookup(&namespace, &last).await.unwrap()),
            "nydus.test/dup"
        );
        assert_eq!(
            lookup.lookup(&namespace, &first).await.unwrap(),
            Claim::Unclaimed
        );
    });
}
