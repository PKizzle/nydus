// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Snapshot metadata store backed by fjall.
//!
//! The Go snapshotter used containerd's bbolt-backed `MetaStore`. The Rust
//! snapshotter keeps the same key/value-shaped persistence model by storing one
//! serialized snapshot record per key in fjall. This avoids a relational schema
//! for inherently bucket-like metadata while still giving us crash-safe,
//! single-writer transactions and straightforward migration tooling.

use anyhow::{Context, Result, bail};
use fjall::{
    KeyspaceCreateOptions, PersistMode, Readable, SingleWriterTxDatabase, SingleWriterTxKeyspace,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::instrument;

const SNAPSHOTS_KEYSPACE: &str = "snapshots";

/// Handle to the fjall snapshot store.
#[derive(Clone)]
pub struct SnapshotStore {
    db: SingleWriterTxDatabase,
    snapshots: SingleWriterTxKeyspace,
}

impl SnapshotStore {
    /// Open (or create) the snapshot store under `store_path`.
    ///
    /// `store_path` is a directory owned by fjall. It intentionally no longer
    /// points at `metadata.db`: older SQLite files can sit next to the new store
    /// until `nydus-migrate` has imported or removed them.
    pub fn open(store_path: &Path) -> Result<Self> {
        if store_path.is_file() {
            bail!(
                "fjall snapshot store path {} is a file; expected a directory",
                store_path.display()
            );
        }
        if let Some(parent) = store_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create snapshot store parent {}",
                    parent.display()
                )
            })?;
        }

        // `manual_journal_persist(true)` because every mutating call below
        // (create/commit/remove/update/set_image_ref/import_snapshot) ends with
        // `self.persist(PersistMode::SyncAll)`. Without this flag fjall ALSO
        // fdatasyncs after every batch (the default), so each operation incurs
        // two fsyncs — wasted on a Pi where journal writes are the slowest
        // step. Owning the persist decision also lets us pair the durability
        // mode with the operation (SyncAll is justified for snapshot metadata).
        //
        // `max_journaling_size` defaults to 512 MiB — far too generous for our
        // workload (snapshot churn is small, the journal grows unboundedly
        // until a memtable flush rotates it). 64 MiB is the documented minimum
        // and keeps recovery time bounded: a journal that small replays in
        // <1s on a Pi 4 even when it's fully populated. Above 64 MiB fjall
        // panics, so this is also the lowest setting available.
        let db = SingleWriterTxDatabase::builder(store_path)
            .manual_journal_persist(true)
            .max_journaling_size(64 * 1024 * 1024)
            .open()
            .with_context(|| {
                format!(
                    "failed to open fjall snapshot store at {}",
                    store_path.display()
                )
            })?;
        let snapshots = db
            .keyspace(SNAPSHOTS_KEYSPACE, KeyspaceCreateOptions::default)
            .context("failed to open fjall snapshots keyspace")?;

        Ok(Self { db, snapshots })
    }

    /// Explicitly persist the journal to disk. Called by the
    /// `containerd-nydus` binary on graceful shutdown so a kill -9 of the
    /// successor (mid-failover) doesn't lose in-flight metadata. Idempotent
    /// and cheap when there's nothing to flush.
    pub fn persist_now(&self) -> Result<()> {
        self.persist()
    }

    /// Look up a snapshot by key and return basic info.
    //
    // `err(level = "debug")` because NotFound is a routine response on this
    // path — containerd's GC walker polls `Stat` for every snapshot reference
    // it holds in its own metadata.db, including stale ones left over from a
    // store migration (legacy SQLite → fjall). Logging each miss at ERROR
    // floods the journal at ~140 lines/min on a node that's otherwise fine
    // (the gRPC layer converts the result to `tonic::Status::not_found` and
    // containerd handles it correctly). Other write paths (`commit`,
    // `create`, `remove`) keep the default ERROR level because a missing key
    // there is genuinely surprising.
    #[instrument(level = "debug", skip(self), err(level = "debug"))]
    pub fn stat(&self, key: &str) -> Result<SnapshotInfo> {
        let value = self
            .snapshots
            .get(key.as_bytes())
            .with_context(|| format!("failed to read snapshot {key}"))?
            .with_context(|| format!("snapshot {key} does not exist"))?;
        decode_snapshot(&value).with_context(|| format!("failed to decode snapshot {key}"))
    }

    /// List all snapshots ordered lexicographically by snapshot key.
    #[instrument(level = "debug", skip(self), err)]
    pub fn list(&self) -> Result<Vec<SnapshotInfo>> {
        let read_tx = self.db.read_tx();
        let mut snapshots = Vec::new();
        for item in read_tx.iter(&self.snapshots) {
            let value = item.value().context("failed to read snapshot value")?;
            snapshots.push(decode_snapshot(&value).context("failed to decode snapshot")?);
        }
        Ok(snapshots)
    }

    /// Create a new active or view snapshot.
    #[instrument(level = "debug", skip(self, labels), fields(parent = ?parent, kind = ?kind), err)]
    pub fn create(
        &self,
        key: &str,
        parent: Option<&str>,
        kind: SnapshotKind,
        fs_driver: &str,
        image_ref: Option<&str>,
        labels: &HashMap<String, String>,
    ) -> Result<()> {
        if matches!(kind, SnapshotKind::Committed) {
            bail!("create only supports active or view snapshots");
        }

        let now = now_unix();
        let info = SnapshotInfo {
            key: key.to_string(),
            parent: parent.map(str::to_string),
            kind: kind.as_str().to_string(),
            fs_driver: fs_driver.to_string(),
            image_ref: image_ref.map(str::to_string),
            created_at: now,
            updated_at: now,
            labels: labels.clone(),
        };
        let encoded = encode_snapshot(&info)?;

        let mut tx = self.db.write_tx();
        if tx
            .get(&self.snapshots, key.as_bytes())
            .with_context(|| format!("failed to check whether snapshot {key} exists"))?
            .is_some()
        {
            bail!("snapshot {key} already exists");
        }
        tx.insert(&self.snapshots, key.as_bytes().to_vec(), encoded);
        tx.commit()
            .with_context(|| format!("failed to create snapshot {key}"))?;
        self.persist()?;

        Ok(())
    }

    /// Commit an active snapshot under a new committed name.
    #[instrument(level = "debug", skip(self, labels), err)]
    pub fn commit(&self, name: &str, key: &str, labels: &HashMap<String, String>) -> Result<()> {
        let mut tx = self.db.write_tx();
        let active_value = tx
            .get(&self.snapshots, key.as_bytes())
            .with_context(|| format!("failed to read active snapshot {key}"))?
            .with_context(|| format!("snapshot {key} does not exist"))?;
        let active = decode_snapshot(&active_value)
            .with_context(|| format!("failed to decode active snapshot {key}"))?;
        if active.kind != SnapshotKind::Active.as_str() {
            bail!("snapshot {key} is not active and cannot be committed");
        }
        if tx
            .get(&self.snapshots, name.as_bytes())
            .with_context(|| format!("failed to check committed snapshot {name}"))?
            .is_some()
        {
            bail!("target committed snapshot {name} already exists");
        }

        let now = now_unix();
        let committed = SnapshotInfo {
            key: name.to_string(),
            parent: active.parent,
            kind: SnapshotKind::Committed.as_str().to_string(),
            fs_driver: active.fs_driver,
            image_ref: active.image_ref,
            created_at: now,
            updated_at: now,
            labels: labels.clone(),
        };

        tx.insert(
            &self.snapshots,
            name.as_bytes().to_vec(),
            encode_snapshot(&committed)?,
        );
        tx.remove(&self.snapshots, key.as_bytes().to_vec());
        tx.commit()
            .with_context(|| format!("failed to commit snapshot {key} as {name}"))?;
        self.persist()?;

        Ok(())
    }

    /// Remove a snapshot row and its labels.
    #[instrument(level = "debug", skip(self), err)]
    pub fn remove(&self, key: &str) -> Result<()> {
        let mut tx = self.db.write_tx();
        if self.child_count_with_reader(&tx, key)? != 0 {
            bail!("snapshot {key} has child snapshots");
        }
        if tx
            .get(&self.snapshots, key.as_bytes())
            .with_context(|| format!("failed to read snapshot {key}"))?
            .is_none()
        {
            bail!("snapshot {key} does not exist");
        }
        tx.remove(&self.snapshots, key.as_bytes().to_vec());
        tx.commit()
            .with_context(|| format!("failed to remove snapshot {key}"))?;
        self.persist()?;
        Ok(())
    }

    /// Check whether a snapshot exists.
    pub fn exists(&self, key: &str) -> Result<bool> {
        self.snapshots
            .get(key.as_bytes())
            .map(|value| value.is_some())
            .with_context(|| format!("failed to check whether snapshot {key} exists"))
    }

    /// Count snapshots that directly use `key` as their parent.
    pub fn child_count(&self, key: &str) -> Result<i64> {
        let read_tx = self.db.read_tx();
        self.child_count_with_reader(&read_tx, key)
    }

    /// Return parent chain from nearest parent to oldest ancestor.
    pub fn parent_chain(&self, parent: &str) -> Result<Vec<SnapshotInfo>> {
        let mut chain = Vec::new();
        let mut next = parent.to_string();
        while !next.is_empty() {
            let info = self.stat(&next)?;
            if info.kind != SnapshotKind::Committed.as_str() {
                bail!("parent snapshot {} is not committed", info.key);
            }
            next = info.parent.clone().unwrap_or_default();
            chain.push(info);
        }
        Ok(chain)
    }

    /// Replace labels for a snapshot.
    pub fn update(&self, key: &str, labels: &[(String, String)]) -> Result<()> {
        let mut tx = self.db.write_tx();
        let value = tx
            .get(&self.snapshots, key.as_bytes())
            .with_context(|| format!("failed to read snapshot {key}"))?
            .with_context(|| format!("snapshot {key} does not exist"))?;
        let mut info =
            decode_snapshot(&value).with_context(|| format!("failed to decode snapshot {key}"))?;
        info.labels = labels.iter().cloned().collect();
        info.updated_at = now_unix();
        tx.insert(
            &self.snapshots,
            key.as_bytes().to_vec(),
            encode_snapshot(&info)?,
        );
        tx.commit()
            .with_context(|| format!("failed to update snapshot {key}"))?;
        self.persist()?;
        Ok(())
    }

    /// Overwrite the persisted `image_ref` for a snapshot. Used to migrate
    /// rows written by an older snapshotter version that stored a blob digest
    /// (e.g. `sha256:…`) in place of a real image reference.
    pub fn set_image_ref(&self, key: &str, image_ref: &str) -> Result<()> {
        let mut tx = self.db.write_tx();
        let value = tx
            .get(&self.snapshots, key.as_bytes())
            .with_context(|| format!("failed to read snapshot {key}"))?
            .with_context(|| format!("snapshot {key} does not exist"))?;
        let mut info =
            decode_snapshot(&value).with_context(|| format!("failed to decode snapshot {key}"))?;
        info.image_ref = Some(image_ref.to_string());
        info.updated_at = now_unix();
        tx.insert(
            &self.snapshots,
            key.as_bytes().to_vec(),
            encode_snapshot(&info)?,
        );
        tx.commit()
            .with_context(|| format!("failed to update image_ref for snapshot {key}"))?;
        self.persist()?;
        Ok(())
    }

    /// Import a complete snapshot record from legacy metadata.
    ///
    /// This is intentionally stricter than an upsert: migration/recovery should
    /// be idempotent by checking [`SnapshotStore::exists`] first, and accidental
    /// overwrites would hide real divergence between containerd and nydus state.
    pub fn import_snapshot(&self, info: SnapshotInfo) -> Result<()> {
        SnapshotKind::from_store_str(&info.kind)
            .with_context(|| format!("snapshot {} has unsupported kind {}", info.key, info.kind))?;

        let mut tx = self.db.write_tx();
        if tx
            .get(&self.snapshots, info.key.as_bytes())
            .with_context(|| format!("failed to check imported snapshot {}", info.key))?
            .is_some()
        {
            bail!("snapshot {} already exists", info.key);
        }
        tx.insert(
            &self.snapshots,
            info.key.as_bytes().to_vec(),
            encode_snapshot(&info)?,
        );
        tx.commit()
            .with_context(|| format!("failed to import snapshot {}", info.key))?;
        self.persist()?;
        Ok(())
    }

    fn child_count_with_reader<R: Readable>(&self, reader: &R, key: &str) -> Result<i64> {
        let mut count = 0i64;
        for item in reader.iter(&self.snapshots) {
            let value = item.value().context("failed to read snapshot value")?;
            let info = decode_snapshot(&value).context("failed to decode snapshot")?;
            if info.parent.as_deref() == Some(key) {
                count += 1;
            }
        }
        Ok(count)
    }

    fn persist(&self) -> Result<()> {
        // `SyncAll` syncs the journal's *file metadata* too, not just the
        // data pages — without it, some filesystems can leave the journal's
        // file size inconsistent after a power loss, which can truncate or
        // duplicate the last batch on the next mount. The extra cost over
        // `SyncData` is one fdatasync vs. one fsync per write; on a Pi this
        // is dominated by SD-card seek latency, not the metadata sync.
        self.db
            .persist(PersistMode::SyncAll)
            .context("failed to persist snapshot metadata")
    }
}

/// Snapshot lifecycle state stored in fjall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    Active,
    Committed,
    View,
}

impl SnapshotKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SnapshotKind::Active => "kind_active",
            SnapshotKind::Committed => "kind_committed",
            SnapshotKind::View => "kind_view",
        }
    }

    pub fn from_store_str(kind: &str) -> Result<Self> {
        match kind {
            "kind_active" => Ok(SnapshotKind::Active),
            "kind_committed" => Ok(SnapshotKind::Committed),
            "kind_view" => Ok(SnapshotKind::View),
            _ => bail!("unsupported snapshot kind {kind}"),
        }
    }

    pub fn from_containerd_kind(kind: u8) -> Result<Self> {
        match kind {
            1 => Ok(SnapshotKind::View),
            2 => Ok(SnapshotKind::Active),
            3 => Ok(SnapshotKind::Committed),
            _ => bail!("unsupported containerd snapshot kind {kind}"),
        }
    }
}

/// Basic snapshot information returned by `stat`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnapshotInfo {
    pub key: String,
    pub parent: Option<String>,
    pub kind: String,
    pub fs_driver: String,
    pub image_ref: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub labels: HashMap<String, String>,
}

fn encode_snapshot(info: &SnapshotInfo) -> Result<Vec<u8>> {
    serde_json::to_vec(info).context("failed to serialize snapshot record")
}

fn decode_snapshot(bytes: &[u8]) -> Result<SnapshotInfo> {
    serde_json::from_slice(bytes).context("failed to deserialize snapshot record")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_creates_empty_store() {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("metadata.fjall");
        let store = SnapshotStore::open(&store_path).unwrap();
        assert!(store_path.is_dir());
        assert_eq!(store.list().unwrap().len(), 0);
    }

    #[test]
    fn stat_returns_not_found() {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("metadata.fjall");
        let store = SnapshotStore::open(&store_path).unwrap();
        assert!(store.stat("nonexistent").is_err());
    }

    #[test]
    fn create_update_list_commit_remove_snapshot() {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("metadata.fjall");
        let store = SnapshotStore::open(&store_path).unwrap();

        let labels =
            HashMap::from([("containerd.io/snapshot.ref".to_string(), "test".to_string())]);
        store
            .create(
                "active-key",
                None,
                SnapshotKind::Active,
                "fusedev",
                Some("image-ref"),
                &labels,
            )
            .unwrap();

        let info = store.stat("active-key").unwrap();
        assert_eq!(info.kind, SnapshotKind::Active.as_str());
        assert_eq!(
            info.labels.get("containerd.io/snapshot.ref").unwrap(),
            "test"
        );
        assert_eq!(store.list().unwrap().len(), 1);

        store
            .update("active-key", &[("updated".to_string(), "true".to_string())])
            .unwrap();
        let info = store.stat("active-key").unwrap();
        assert_eq!(info.labels.get("updated").unwrap(), "true");
        assert!(!info.labels.contains_key("containerd.io/snapshot.ref"));

        let commit_labels = HashMap::from([("committed".to_string(), "yes".to_string())]);
        store
            .commit("committed-name", "active-key", &commit_labels)
            .unwrap();
        assert!(store.stat("active-key").is_err());
        let committed = store.stat("committed-name").unwrap();
        assert_eq!(committed.kind, SnapshotKind::Committed.as_str());
        assert_eq!(committed.labels.get("committed").unwrap(), "yes");

        store.remove("committed-name").unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn committed_snapshot_with_child_cannot_be_removed() {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("metadata.fjall");
        let store = SnapshotStore::open(&store_path).unwrap();
        let labels = HashMap::new();

        store
            .create(
                "base-active",
                None,
                SnapshotKind::Active,
                "fusedev",
                None,
                &labels,
            )
            .unwrap();
        store.commit("base", "base-active", &labels).unwrap();
        store
            .create(
                "child-active",
                Some("base"),
                SnapshotKind::Active,
                "fusedev",
                None,
                &labels,
            )
            .unwrap();

        assert!(store.remove("base").is_err());
        store.remove("child-active").unwrap();
        store.remove("base").unwrap();
    }

    #[test]
    fn store_persists_across_reopen() {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("metadata.fjall");
        let labels = HashMap::from([("persisted".to_string(), "true".to_string())]);
        {
            let store = SnapshotStore::open(&store_path).unwrap();
            store
                .create(
                    "active-key",
                    None,
                    SnapshotKind::Active,
                    "fusedev",
                    None,
                    &labels,
                )
                .unwrap();
        }

        let store = SnapshotStore::open(&store_path).unwrap();
        let info = store.stat("active-key").unwrap();
        assert_eq!(info.labels.get("persisted").unwrap(), "true");
    }

    /// Validates the `manual_journal_persist(true)` + `persist_now()` contract
    /// the snapshotter binary relies on across SIGTERM: with manual persist
    /// enabled, fjall does NOT auto-flush after each batch, so we own the
    /// fsync. `create()` already calls `persist()` internally, but
    /// `persist_now()` is the public flush hook the binary invokes in its
    /// shutdown path. This test asserts the explicit hook is sufficient for
    /// durability — i.e. data created and then `persist_now()`'d is readable
    /// after a fresh open, without relying on Drop to flush.
    #[test]
    fn persist_now_flushes_journal_for_failover_path() {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("metadata.fjall");
        let labels = HashMap::from([("failover".to_string(), "armed".to_string())]);
        {
            let store = SnapshotStore::open(&store_path).unwrap();
            store
                .create(
                    "armed-key",
                    None,
                    SnapshotKind::Active,
                    "fusedev",
                    None,
                    &labels,
                )
                .unwrap();
            // The binary's shutdown path calls this before exiting on the
            // fdstore failover branch. If this is a no-op or wrong, the
            // successor would start with empty state.
            store.persist_now().unwrap();
        }

        let store = SnapshotStore::open(&store_path).unwrap();
        let info = store.stat("armed-key").unwrap();
        assert_eq!(info.labels.get("failover").unwrap(), "armed");
    }

    #[test]
    fn import_snapshot_preserves_legacy_record() {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("metadata.fjall");
        let store = SnapshotStore::open(&store_path).unwrap();
        let info = SnapshotInfo {
            key: "legacy-committed".to_string(),
            parent: None,
            kind: SnapshotKind::Committed.as_str().to_string(),
            fs_driver: "fusedev".to_string(),
            image_ref: Some("docker.io/example/image:nydus".to_string()),
            created_at: 123,
            updated_at: 456,
            labels: HashMap::from([(
                "containerd.io/snapshot.ref".to_string(),
                "docker.io/example/image:nydus".to_string(),
            )]),
        };

        store.import_snapshot(info.clone()).unwrap();
        let imported = store.stat("legacy-committed").unwrap();
        assert_eq!(imported.parent, info.parent);
        assert_eq!(imported.kind, info.kind);
        assert_eq!(imported.fs_driver, info.fs_driver);
        assert_eq!(imported.image_ref, info.image_ref);
        assert_eq!(imported.created_at, 123);
        assert_eq!(imported.updated_at, 456);
        assert!(store.import_snapshot(info).is_err());
    }
}
