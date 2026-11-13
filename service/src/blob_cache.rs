// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Blob cache manager to cache RAFS meta/data blob objects.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use compio::buf::{BufResult, IoBufMut};
use compio::fs::File;
use compio::io::AsyncReadAt;
use compio::runtime::ResumeUnwind;
use nydus_api::{
    BLOB_CACHE_TYPE_DATA_BLOB, BLOB_CACHE_TYPE_META_BLOB, BlobCacheEntry, BlobCacheList,
    BlobCacheObjectId, ConfigV2,
};
use nydus_rafs::metadata::layout::v6::{EROFS_BLOCK_BITS_12, EROFS_BLOCK_SIZE_4096};
use nydus_rafs::metadata::{RafsBlobExtraInfo, RafsSuper, RafsSuperFlags};
use nydus_storage::cache::BlobCache;
use nydus_storage::device::BlobInfo;
use nydus_storage::factory::BLOB_FACTORY;
use serde::Serialize;

use crate::{Error, Result};

const ID_SPLITTER: &str = "/";

/// Generate keys for cached blob objects from domain identifiers and blob identifiers.
pub fn generate_blob_key(domain_id: &str, blob_id: &str) -> String {
    if domain_id.is_empty() {
        blob_id.to_string()
    } else {
        format!("{}{}{}", domain_id, ID_SPLITTER, blob_id)
    }
}

/// Public, non-secret view of a blob cache object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobCacheObjectInfo {
    /// Type of blob object, bootstrap or data blob.
    #[serde(rename = "type")]
    pub blob_type: String,
    /// Domain id used to group cached blobs.
    pub domain_id: String,
    /// Blob id without domain scoping.
    #[serde(rename = "id")]
    pub blob_id: String,
    /// Number of active references to the blob object.
    pub ref_count: u32,
}

/// Public list response for cached blob objects.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct BlobCacheObjectList {
    /// Matching blob objects.
    pub blobs: Vec<BlobCacheObjectInfo>,
}

/// Configuration information for a cached metadata blob.
pub struct MetaBlobConfig {
    blob_id: String,
    scoped_blob_id: String,
    path: PathBuf,
    config: Arc<ConfigV2>,
    blobs: Mutex<Vec<Arc<DataBlobConfig>>>,
    blob_extra_infos: HashMap<String, RafsBlobExtraInfo>,
    is_tarfs_mode: bool,
    /// `log2` of the EROFS block size recorded in the bootstrap superblock.
    block_bits: u8,
}

impl MetaBlobConfig {
    /// Get blob id.
    pub fn blob_id(&self) -> &str {
        &self.blob_id
    }

    /// Get file path to access the meta blob.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the ['ConfigV2'] object associated with the cached data blob.
    pub fn config_v2(&self) -> &Arc<ConfigV2> {
        &self.config
    }

    pub fn get_blobs(&self) -> Vec<Arc<DataBlobConfig>> {
        self.blobs.lock().unwrap().clone()
    }

    /// Get optional extra information associated with a blob object.
    pub fn get_blob_extra_info(&self, blob_id: &str) -> Option<&RafsBlobExtraInfo> {
        self.blob_extra_infos.get(blob_id)
    }

    /// Check whether the filesystem is in `TARFS` mode.
    pub fn is_tarfs_mode(&self) -> bool {
        self.is_tarfs_mode
    }

    /// Get `log2` of the filesystem's EROFS block size, the unit of its block addresses.
    pub fn block_bits(&self) -> u8 {
        self.block_bits
    }

    fn add_data_blob(&self, blob: Arc<DataBlobConfig>) {
        self.blobs.lock().unwrap().push(blob);
    }
}

/// Configuration information for a cached data blob.
pub struct DataBlobConfig {
    scoped_blob_id: String,
    blob_info: Arc<BlobInfo>,
    config: Arc<ConfigV2>,
    ref_count: AtomicU32,
}

impl DataBlobConfig {
    /// Get the [`BlobInfo`](https://docs.rs/nydus-storage/latest/nydus_storage/device/struct.BlobInfo.html) object associated with the cached data blob.
    pub fn blob_info(&self) -> &Arc<BlobInfo> {
        &self.blob_info
    }

    /// Get the ['ConfigV2'] object associated with the cached data blob.
    pub fn config_v2(&self) -> &Arc<ConfigV2> {
        &self.config
    }
}

/// Configuration information for a cached metadata/data blob.
#[derive(Clone)]
pub enum BlobConfig {
    /// Configuration information for cached meta blob objects.
    MetaBlob(Arc<MetaBlobConfig>),
    /// Configuration information for cached data blob objects.
    DataBlob(Arc<DataBlobConfig>),
}

impl BlobConfig {
    /// Get the ['ConfigV2'] object associated with the cached data blob.
    pub fn config_v2(&self) -> &Arc<ConfigV2> {
        match self {
            BlobConfig::MetaBlob(v) => v.config_v2(),
            BlobConfig::DataBlob(v) => v.config_v2(),
        }
    }

    fn new_data_blob(domain_id: String, blob_info: Arc<BlobInfo>, config: Arc<ConfigV2>) -> Self {
        let scoped_blob_id = generate_blob_key(&domain_id, &blob_info.blob_id());

        BlobConfig::DataBlob(Arc::new(DataBlobConfig {
            blob_info,
            scoped_blob_id,
            config,
            ref_count: AtomicU32::new(1),
        }))
    }

    fn new_meta_blob(
        domain_id: String,
        blob_id: String,
        path: PathBuf,
        config: Arc<ConfigV2>,
        blob_extra_infos: HashMap<String, RafsBlobExtraInfo>,
        is_tarfs_mode: bool,
        block_bits: u8,
    ) -> Self {
        let scoped_blob_id = generate_blob_key(&domain_id, &blob_id);

        BlobConfig::MetaBlob(Arc::new(MetaBlobConfig {
            blob_id,
            scoped_blob_id,
            path,
            config,
            blobs: Mutex::new(Vec::new()),
            blob_extra_infos,
            is_tarfs_mode,
            block_bits,
        }))
    }

    fn key(&self) -> &str {
        match self {
            BlobConfig::MetaBlob(o) => &o.scoped_blob_id,
            BlobConfig::DataBlob(o) => &o.scoped_blob_id,
        }
    }

    fn meta_config(&self) -> Option<Arc<MetaBlobConfig>> {
        match self {
            BlobConfig::MetaBlob(o) => Some(o.clone()),
            BlobConfig::DataBlob(_o) => None,
        }
    }

    fn to_object_info(&self, domain_id: &str) -> BlobCacheObjectInfo {
        match self {
            BlobConfig::MetaBlob(o) => BlobCacheObjectInfo {
                blob_type: BLOB_CACHE_TYPE_META_BLOB.to_string(),
                domain_id: domain_id.to_string(),
                blob_id: o.blob_id.clone(),
                ref_count: 1,
            },
            BlobConfig::DataBlob(o) => BlobCacheObjectInfo {
                blob_type: BLOB_CACHE_TYPE_DATA_BLOB.to_string(),
                domain_id: domain_id.to_string(),
                blob_id: o.blob_info.blob_id(),
                ref_count: o.ref_count.load(Ordering::Acquire),
            },
        }
    }
}

#[derive(Default)]
struct BlobCacheState {
    id_to_config_map: HashMap<String, BlobConfig>,
}

impl BlobCacheState {
    fn new() -> Self {
        Self::default()
    }

    fn try_add(&mut self, config: BlobConfig) -> Result<()> {
        let key = config.key();

        if let Some(entry) = self.id_to_config_map.get(key) {
            match entry {
                BlobConfig::MetaBlob(_o) => {
                    // Meta blob must be unique.
                    return Err(Error::AlreadyExists);
                }
                BlobConfig::DataBlob(o) => {
                    // Data blob is reference counted.
                    o.ref_count.fetch_add(1, Ordering::AcqRel);
                }
            }
        } else {
            self.id_to_config_map.insert(key.to_owned(), config);
        }

        Ok(())
    }

    fn remove(&mut self, param: &BlobCacheObjectId) -> Result<()> {
        if param.blob_id.is_empty() && !param.domain_id.is_empty() {
            // Remove all blobs associated with the domain.
            let scoped_blob_prefix = format!("{}{}", param.domain_id, ID_SPLITTER);
            self.id_to_config_map.retain(|_k, v| match v {
                BlobConfig::MetaBlob(o) => !o.scoped_blob_id.starts_with(&scoped_blob_prefix),
                BlobConfig::DataBlob(o) => !o.scoped_blob_id.starts_with(&scoped_blob_prefix),
            });
        } else {
            let mut data_blobs = Vec::new();
            let mut is_meta = false;
            let scoped_blob_prefix = generate_blob_key(&param.domain_id, &param.blob_id);

            match self.id_to_config_map.get(&scoped_blob_prefix) {
                None => {
                    return Err(Error::BlobCache(
                        "blob_cache: cache entry not found".to_string(),
                    ));
                }
                Some(BlobConfig::MetaBlob(o)) => {
                    is_meta = true;
                    data_blobs = o.blobs.lock().unwrap().clone();
                }
                Some(BlobConfig::DataBlob(o)) => {
                    data_blobs.push(o.clone());
                }
            }

            for entry in data_blobs {
                if entry.ref_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                    self.id_to_config_map.remove(&entry.scoped_blob_id);
                }
            }

            if is_meta {
                self.id_to_config_map.remove(&scoped_blob_prefix);
            }
        }

        Ok(())
    }

    fn get(&self, key: &str) -> Option<BlobConfig> {
        self.id_to_config_map.get(key).cloned()
    }

    fn list(&self, param: &BlobCacheObjectId) -> Result<BlobCacheObjectList> {
        if param.domain_id.is_empty() {
            return Err(Error::InvalidArguments(
                "blob_cache: missing domain id".to_string(),
            ));
        }

        if !param.blob_id.is_empty() {
            let scoped_blob_id = generate_blob_key(&param.domain_id, &param.blob_id);
            let entry = self
                .id_to_config_map
                .get(&scoped_blob_id)
                .ok_or_else(|| Error::BlobCache("blob_cache: cache entry not found".to_string()))?;
            return Ok(BlobCacheObjectList {
                blobs: vec![entry.to_object_info(&param.domain_id)],
            });
        }

        let scoped_blob_prefix = format!("{}{}", param.domain_id, ID_SPLITTER);
        let mut blobs: Vec<BlobCacheObjectInfo> = self
            .id_to_config_map
            .iter()
            .filter_map(|(key, entry)| {
                if key.starts_with(&scoped_blob_prefix) {
                    Some(entry.to_object_info(&param.domain_id))
                } else {
                    None
                }
            })
            .collect();

        blobs.sort_by(|a, b| {
            a.blob_type
                .cmp(&b.blob_type)
                .then_with(|| a.blob_id.cmp(&b.blob_id))
        });

        Ok(BlobCacheObjectList { blobs })
    }
}

/// Structure to manage and cache RAFS meta/data blob objects.
#[derive(Default)]
pub struct BlobCacheMgr {
    state: Mutex<BlobCacheState>,
}

impl BlobCacheMgr {
    /// Create a new instance of `BlobCacheMgr`.
    pub fn new() -> Self {
        BlobCacheMgr {
            state: Mutex::new(BlobCacheState::new()),
        }
    }

    /// Add a meta/data blob to be managed by the cache manager.
    ///
    /// When adding a RAFS meta blob to the cache manager, all data blobs referenced by the
    /// bootstrap blob will also be added to the cache manager too. It may be used to add a RAFS
    /// container image to the cache manager.
    ///
    /// Domains are used to control the blob sharing scope. All meta and data blobs associated
    /// with the same domain will be shared/reused, but blobs associated with different domains are
    /// isolated. The `domain_id` is used to identify the associated domain.
    pub fn add_blob_entry(&self, entry: &BlobCacheEntry) -> Result<()> {
        match entry.blob_type.as_str() {
            BLOB_CACHE_TYPE_META_BLOB => {
                let (path, config) = self.get_meta_info(entry)?;
                self.add_meta_object(&entry.domain_id, &entry.blob_id, path, config)
                    // Never the entry itself: its backend config may carry registry credentials.
                    .inspect_err(|e| {
                        warn!(
                            "blob_cache: failed to add cache entry for meta blob {} in domain {}: {}",
                            entry.blob_id, entry.domain_id, e
                        );
                    })
            }
            BLOB_CACHE_TYPE_DATA_BLOB => Err(Error::InvalidArguments(format!(
                "blob_cache: invalid data blob cache entry: {:?}",
                entry.clone_without_secrets()
            ))),
            _ => Err(Error::InvalidArguments(format!(
                "blob_cache: invalid blob cache entry, {:?}",
                entry.clone_without_secrets()
            ))),
        }
    }

    /// Add a list of meta/data blobs to be cached by the cache manager.
    ///
    /// If failed to add some blob, the blobs already added won't be rolled back.
    pub fn add_blob_list(&self, blobs: &BlobCacheList) -> Result<()> {
        for entry in blobs.blobs.iter() {
            self.add_blob_entry(entry)?;
        }

        Ok(())
    }

    /// Remove a meta/data blob object from the cache manager.
    pub fn remove_blob_entry(&self, param: &BlobCacheObjectId) -> Result<()> {
        self.get_state().remove(param)
    }

    /// List cached blob objects matching the requested domain and optional blob id.
    pub fn list_blob_entries(&self, param: &BlobCacheObjectId) -> Result<BlobCacheObjectList> {
        self.get_state().list(param)
    }

    /// Get configuration information of the cached blob with specified `key`.
    pub fn get_config(&self, key: &str) -> Option<BlobConfig> {
        self.get_state().get(key)
    }

    /// Collect the configuration of every managed data blob.
    ///
    /// Used by the fanotify on-demand handler to build the set of [`DataBlob`] objects whose
    /// sparse backing files it must populate when the kernel raises `FAN_PRE_ACCESS` events.
    pub fn get_all_data_blobs(&self) -> Vec<Arc<DataBlobConfig>> {
        self.get_state()
            .id_to_config_map
            .values()
            .filter_map(|c| match c {
                BlobConfig::DataBlob(d) => Some(d.clone()),
                BlobConfig::MetaBlob(_) => None,
            })
            .collect()
    }

    #[inline]
    fn get_state(&self) -> MutexGuard<'_, BlobCacheState> {
        self.state.lock().unwrap()
    }

    fn get_meta_info(&self, entry: &BlobCacheEntry) -> Result<(PathBuf, Arc<ConfigV2>)> {
        let config = entry.blob_config.as_ref().ok_or_else(|| {
            Error::InvalidArguments(
                "blob_cache: missing blob cache configuration information".to_string(),
            )
        })?;

        if entry.blob_id.contains(ID_SPLITTER) {
            return Err(Error::InvalidArguments(
                "blob_cache: `blob_id` for meta blob is invalid".to_string(),
            ));
        } else if entry.domain_id.contains(ID_SPLITTER) {
            return Err(Error::InvalidArguments(
                "blob_cache: `domain_id` for meta blob is invalid".to_string(),
            ));
        }

        let path = config.metadata_path.clone().unwrap_or_default();
        if path.is_empty() {
            return Err(Error::InvalidArguments(
                "blob_cache: `config.metadata_path` for meta blob is empty".to_string(),
            ));
        }
        let path = Path::new(&path).canonicalize().map_err(|_e| {
            Error::InvalidArguments(format!(
                "blob_cache: `config.metadata_path={}` for meta blob is invalid",
                path
            ))
        })?;
        if !path.is_file() {
            return Err(Error::InvalidArguments(
                "blob_cache: `config.metadata_path` for meta blob is not a file".to_string(),
            ));
        }

        // Validate type of backend and cache.
        if config.cache.is_filecache() {
            // Validate the working directory for filecache
            let cache_config = config
                .cache
                .get_filecache_config()
                .map_err(|e| Error::InvalidConfig(e.to_string()))?;
            let path2 = Path::new(&cache_config.work_dir);
            let path2 = path2.canonicalize().map_err(|_e| {
                Error::BlobCache(
                    "blob_cache: `config.cache_config.work_dir` is invalid".to_string(),
                )
            })?;
            if !path2.is_dir() {
                return Err(Error::InvalidArguments(
                    "blob_cache: `config.cache_config.work_dir` is not a directory".to_string(),
                ));
            }
        } else if config.cache.is_fanotify() {
            // Validate the working directory for fanotify
            let cache_config = config
                .cache
                .get_fanotify_config()
                .map_err(|e| Error::InvalidConfig(e.to_string()))?;
            let path2 = Path::new(&cache_config.work_dir);
            let path2 = path2.canonicalize().map_err(|_e| {
                Error::BlobCache(
                    "blob_cache: `config.cache_config.work_dir` is invalid".to_string(),
                )
            })?;
            if !path2.is_dir() {
                return Err(Error::InvalidArguments(
                    "blob_cache: `config.cache_config.work_dir` is not a directory".to_string(),
                ));
            }
        } else {
            return Err(Error::InvalidArguments(
                "blob_cache: unknown cache type".to_string(),
            ));
        }

        let config: Arc<ConfigV2> = Arc::new(config.into());
        config.internal.set_blob_accessible(true);

        Ok((path, config))
    }

    fn add_meta_object(
        &self,
        domain_id: &str,
        id: &str,
        path: PathBuf,
        config: Arc<ConfigV2>,
    ) -> Result<()> {
        let (rs, _) = RafsSuper::load_from_file(&path, config.clone(), false)?;
        if rs.meta.is_v5() {
            return Err(Error::InvalidArguments(
                "blob_cache: RAFSv5 image is not supported".to_string(),
            ));
        }

        let blob_extra_infos = rs.superblock.get_blob_extra_infos()?;
        let meta = BlobConfig::new_meta_blob(
            domain_id.to_string(),
            id.to_string(),
            path,
            config,
            blob_extra_infos,
            rs.meta.flags.contains(RafsSuperFlags::TARTFS_MODE),
            rs.meta.blkszbits,
        );
        // Safe to unwrap because it's a meta blob object.
        let meta_obj = meta.meta_config().unwrap();
        let mut state = self.get_state();
        state.try_add(meta)?;

        // Try to add the referenced data blob object if it doesn't exist yet.
        for bi in rs.superblock.get_blob_infos() {
            debug!(
                "blob_cache: add data blob {} to domain {}",
                &bi.blob_id(),
                domain_id
            );
            let data_blob =
                BlobConfig::new_data_blob(domain_id.to_string(), bi, meta_obj.config.clone());
            let data_blob_config = match &data_blob {
                BlobConfig::DataBlob(entry) => entry.clone(),
                _ => panic!("blob_cache: internal error"),
            };

            if let Err(e) = state.try_add(data_blob) {
                // Rollback added bootstrap/data blobs.
                let id = BlobCacheObjectId {
                    domain_id: domain_id.to_string(),
                    blob_id: id.to_string(),
                };
                let _ = state.remove(&id);
                return Err(e);
            }

            // Associate the data blob with the bootstrap blob.
            meta_obj.add_data_blob(data_blob_config);
        }

        Ok(())
    }
}

/// Structure representing a cached metadata blob.
pub struct MetaBlob {
    file: File,
    size: u64,
}

impl MetaBlob {
    /// Create a new [MetaBlob] object from
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        // compio's File has no fd-based constructor, so open the metadata blob by path
        // directly through compio (io_uring); this is read-only positional I/O.
        let file = File::open(path.as_ref()).await.inspect_err(|_e| {
            warn!(
                "blob_cache: failed to open metadata blob {}",
                path.as_ref().display()
            );
        })?;
        let md = file.metadata().await.inspect_err(|_e| {
            warn!(
                "blob_cache: failed to get metadata about metadata blob {}",
                path.as_ref().display()
            );
        })?;
        let size = md.len();
        if size % EROFS_BLOCK_SIZE_4096 != 0 || (size >> EROFS_BLOCK_BITS_12) > u32::MAX as u64 {
            return Err(Error::InvalidArguments(format!(
                "blob_cache: metadata blob size (0x{:x}) is invalid",
                size
            )));
        }

        Ok(MetaBlob { file, size })
    }

    /// Get size of the metadata blob in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Read data from the cached metadata blob in asynchronous mode.
    pub async fn async_read<T: IoBufMut>(&self, pos: u64, buf: T) -> (Result<usize>, T) {
        let BufResult(res, buf) = self.file.read_at(buf, pos).await;
        (res.map_err(Error::from), buf)
    }

    pub fn file(&self) -> &File {
        &self.file
    }
}

/// Structure representing a cached data blob.
pub struct DataBlob {
    blob_id: String,
    blob: Arc<dyn BlobCache>,
    blob_info: Arc<BlobInfo>,
    file: File,
}

impl DataBlob {
    /// Create a new instance of [DataBlob].
    pub async fn new(config: &Arc<DataBlobConfig>) -> Result<Self> {
        let blob_id = config.blob_info().blob_id();
        let blob_info = config.blob_info().clone();
        let blob = BLOB_FACTORY
            .new_blob_cache(config.config_v2(), &config.blob_info, "/")
            .inspect_err(|_e| {
                warn!(
                    "blob_cache: failed to create cache object for blob {}",
                    blob_id
                );
            })?;

        match blob.get_blob_object() {
            Some(obj) => {
                // compio's File has no fd-based constructor, so resolve the cache file's real
                // path from the blob object's fd and re-open the same inode via compio (io_uring).
                // `/proc/self/fd` avoids assuming the `<work_dir>/<blob_id>.blob.data` layout and
                // transparently handles hardlinked cache files.
                let path = std::fs::read_link(format!("/proc/self/fd/{}", obj.as_raw_fd()))
                    .map_err(|e| {
                        Error::BlobCache(format!(
                            "blob_cache: failed to resolve cache path for blob {}: {}",
                            blob_id, e
                        ))
                    })?;
                let file = File::open(&path).await.map_err(|e| {
                    Error::BlobCache(format!(
                        "blob_cache: failed to open data blob {} at {}: {}",
                        blob_id,
                        path.display(),
                        e
                    ))
                })?;
                Ok(DataBlob {
                    blob_id,
                    blob,
                    blob_info,
                    file,
                })
            }
            None => Err(Error::BlobCache(format!(
                "blob_cache: failed to get BlobObject for blob {}",
                blob_id
            ))),
        }
    }

    /// Ensure a range of data is available in the local cache, downloading if necessary.
    pub async fn async_fetch(&self, pos: u64, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }

        let blob = self.blob.clone();
        let blob_id = self.blob_id.clone();

        // Blocking thread pool is needed because reqwest::blocking may be called. Use compio's
        // blocking pool (not tokio's) since this runs inside the compio runtime; resume_unwind
        // re-raises a panic in the blocking closure and otherwise yields its `Result`.
        compio::runtime::spawn_blocking(move || -> Result<()> {
            let obj = blob.get_blob_object().ok_or_else(|| {
                Error::BlobCache(format!(
                    "blob_cache: failed to get BlobObject for blob {}",
                    blob_id
                ))
            })?;
            Ok(obj.fetch_range_uncompressed(pos, len as u64)?)
        })
        .await
        .resume_unwind()
        .unwrap_or_else(|| {
            Err(Error::BlobCache(
                "blob_cache: blob fetch task was cancelled".to_string(),
            ))
        })
    }

    /// Read data from the cached data blob in asynchronous mode.
    pub async fn async_read<T: IoBufMut>(&self, pos: u64, mut buf: T) -> (Result<usize>, T) {
        let len = buf.buf_capacity();
        match self.async_fetch(pos, len).await {
            Ok(()) => {
                let BufResult(res, buf) = self.file.read_at(buf, pos).await;
                (res.map_err(Error::from), buf)
            }
            Err(e) => (Err(e), buf),
        }
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn blob(&self) -> &Arc<dyn BlobCache> {
        &self.blob
    }

    pub fn blob_info(&self) -> &Arc<BlobInfo> {
        &self.blob_info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Miri cannot map files, so under Miri bootstraps are copied into memory.
    const METADATA_SOURCE: nydus_api::MetadataSource = if cfg!(miri) {
        nydus_api::MetadataSource::Read
    } else {
        nydus_api::MetadataSource::Mmap
    };

    fn create_factory_config() -> String {
        let config = r#"
        {
            "type": "bootstrap",
            "id": "bootstrap1",
            "domain_id": "userid1",
            "config": {
                "id": "factory1",
                "backend_type": "localfs",
                "backend_config": {
                    "dir": "/tmp/nydus"
                },
                "cache_type": "fanotify",
                "cache_config": {
                    "work_dir": "/tmp/nydus"
                },
                "metadata_path": "/tmp/nydus/bootstrap1"
            }
          }"#;

        config.to_string()
    }

    #[test]
    fn test_generate_blob_key() {
        assert_eq!(&generate_blob_key("", "blob1"), "blob1");
        assert_eq!(&generate_blob_key("domain1", "blob1"), "domain1/blob1");
    }

    #[test]
    fn test_blob_cache_entry() {
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.path().join("bootstrap1");
        std::fs::write(path, "metadata").unwrap();
        let cfg = create_factory_config();
        let content = cfg.replace("/tmp/nydus", tmpdir.path().to_str().unwrap());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());
        let blob_config = entry.blob_config.as_ref().unwrap();

        assert_eq!(&entry.blob_type, "bootstrap");
        assert_eq!(&entry.blob_id, "bootstrap1");
        assert_eq!(&entry.domain_id, "userid1");
        assert_eq!(&blob_config.id, "factory1");
        assert_eq!(&blob_config.backend.backend_type, "localfs");
        assert_eq!(&blob_config.cache.cache_type, "fanotify");
        assert!(blob_config.metadata_path.is_some());
        assert!(blob_config.backend.localfs.is_some());
        assert!(blob_config.cache.fanotify.is_some());

        let mgr = BlobCacheMgr::new();
        let (path, config) = mgr.get_meta_info(&entry).unwrap();
        let backend_cfg = config.get_backend_config().unwrap();
        let cache_cfg = config.get_cache_config().unwrap();
        assert_eq!(path, tmpdir.path().join("bootstrap1"));
        assert_eq!(&config.id, "factory1");
        assert_eq!(&backend_cfg.backend_type, "localfs");
        assert_eq!(&cache_cfg.cache_type, "fanotify");

        let blob = MetaBlobConfig {
            blob_id: "123456789-123".to_string(),
            scoped_blob_id: "domain1".to_string(),
            path: path.clone(),
            config,
            blobs: Mutex::new(Vec::new()),
            blob_extra_infos: HashMap::new(),
            is_tarfs_mode: false,
            block_bits: EROFS_BLOCK_BITS_12,
        };
        assert_eq!(blob.path(), &path);
        assert_eq!(blob.blob_id(), "123456789-123");
    }

    #[test]
    fn test_invalid_blob_id() {
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.path().join("bootstrap1");
        std::fs::write(path, "metadata").unwrap();
        let config = create_factory_config();
        let content = config.replace("/tmp/nydus", tmpdir.path().to_str().unwrap());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        let mgr = BlobCacheMgr::new();

        entry.blob_id = "domain2/blob1".to_string();
        mgr.get_meta_info(&entry).unwrap_err();
    }

    #[test]
    fn test_blob_cache_list() {
        let config = r#"
         {
            "blobs" : [
                {
                    "type": "bootstrap",
                    "id": "bootstrap1",
                    "domain_id": "userid1",
                    "config": {
                        "id": "factory1",
                        "backend_type": "localfs",
                        "backend_config": {
                            "dir": "/tmp/nydus"
                        },
                        "cache_type": "fanotify",
                        "cache_config": {
                            "work_dir": "/tmp/nydus"
                        },
                        "metadata_path": "/tmp/nydus/bootstrap1"
                    }
                },
                {
                    "type": "bootstrap",
                    "id": "bootstrap2",
                    "domain_id": "userid2",
                    "config": {
                        "id": "factory1",
                        "backend_type": "localfs",
                        "backend_config": {
                            "dir": "/tmp/nydus"
                        },
                        "cache_type": "fanotify",
                        "cache_config": {
                            "work_dir": "/tmp/nydus"
                        },
                        "metadata_path": "/tmp/nydus/bootstrap2"
                    }
                }
            ]
         }"#;
        let mut list: BlobCacheList = serde_json::from_str(config).unwrap();
        assert!(list.blobs[0].prepare_configuration_info());

        assert_eq!(list.blobs.len(), 2);
        assert_eq!(&list.blobs[0].blob_type, "bootstrap");
        assert_eq!(&list.blobs[0].blob_id, "bootstrap1");
        let blob_config = &list.blobs[0].blob_config.as_ref().unwrap();
        assert_eq!(&blob_config.id, "factory1");
        assert_eq!(&blob_config.backend.backend_type, "localfs");
        assert_eq!(&blob_config.cache.cache_type, "fanotify");
        assert_eq!(&list.blobs[1].blob_type, "bootstrap");
        assert_eq!(&list.blobs[1].blob_id, "bootstrap2");
    }

    #[test]
    fn test_add_bootstrap() {
        let tmpdir = TempDir::new().unwrap();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");

        let config = r#"
        {
            "type": "bootstrap",
            "id": "rafs-v6",
            "domain_id": "domain2",
            "config_v2": {
                "version": 2,
                "id": "factory1",
                "backend": {
                    "type": "localfs",
                    "localfs": {
                        "dir": "/tmp/nydus"
                    }
                },
                "cache": {
                    "type": "fanotify",
                    "fanotify": {
                        "work_dir": "/tmp/nydus"
                    }
                },
                "metadata_path": "RAFS_V5"
            }
          }"#;
        let content = config
            .replace("/tmp/nydus", tmpdir.path().to_str().unwrap())
            .replace("RAFS_V5", &source_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());
        entry.blob_config.as_mut().unwrap().metadata_source = METADATA_SOURCE;

        let mgr = BlobCacheMgr::new();
        mgr.add_blob_entry(&entry).unwrap();
        let blob_id = generate_blob_key(&entry.domain_id, &entry.blob_id);
        assert!(mgr.get_config(&blob_id).is_some());

        // add the same entry will trigger an error
        assert!(mgr.add_blob_entry(&entry).is_err());

        // Check existence of data blob referenced by the bootstrap.
        let key = generate_blob_key(
            &entry.domain_id,
            "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef",
        );
        assert!(mgr.get_config(&key).is_some());

        assert_eq!(mgr.get_state().id_to_config_map.len(), 2);

        entry.blob_id = "rafs-v6-cloned".to_string();
        let blob_id_cloned = generate_blob_key(&entry.domain_id, &entry.blob_id);
        mgr.add_blob_entry(&entry).unwrap();
        assert_eq!(mgr.get_state().id_to_config_map.len(), 3);
        assert!(mgr.get_config(&blob_id).is_some());
        assert!(mgr.get_config(&blob_id_cloned).is_some());

        mgr.remove_blob_entry(&BlobCacheObjectId {
            domain_id: entry.domain_id.clone(),
            blob_id: "rafs-v6".to_string(),
        })
        .unwrap();
        assert_eq!(mgr.get_state().id_to_config_map.len(), 2);
        assert!(mgr.get_config(&blob_id).is_none());
        assert!(mgr.get_config(&blob_id_cloned).is_some());

        mgr.remove_blob_entry(&BlobCacheObjectId {
            domain_id: entry.domain_id,
            blob_id: "rafs-v6-cloned".to_string(),
        })
        .unwrap();
        assert_eq!(mgr.get_state().id_to_config_map.len(), 0);
        assert!(mgr.get_config(&blob_id).is_none());
        assert!(mgr.get_config(&blob_id_cloned).is_none());
    }

    #[test]
    fn test_get_meta_info_rejects_invalid_metadata_path() {
        let tmpdir = TempDir::new().unwrap();
        let config = create_factory_config();
        let content = config.replace("/tmp/nydus", tmpdir.path().to_str().unwrap());
        let mgr = BlobCacheMgr::new();

        let mut empty_path_entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(empty_path_entry.prepare_configuration_info());
        empty_path_entry.blob_config.as_mut().unwrap().metadata_path = Some(String::new());
        assert!(mgr.get_meta_info(&empty_path_entry).is_err());

        let mut dir_path_entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(dir_path_entry.prepare_configuration_info());
        dir_path_entry.blob_config.as_mut().unwrap().metadata_path =
            Some(tmpdir.path().to_str().unwrap().to_string());
        assert!(mgr.get_meta_info(&dir_path_entry).is_err());

        let mut missing_path_entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(missing_path_entry.prepare_configuration_info());
        missing_path_entry
            .blob_config
            .as_mut()
            .unwrap()
            .metadata_path = Some(tmpdir.path().join("missing.boot").display().to_string());
        assert!(mgr.get_meta_info(&missing_path_entry).is_err());
    }

    #[test]
    fn test_remove_blob_entry_by_domain() {
        let tmpdir = TempDir::new().unwrap();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");

        let config = r#"
        {
            "type": "bootstrap",
            "id": "rafs-v6",
            "domain_id": "domain2",
            "config_v2": {
                "version": 2,
                "id": "factory1",
                "backend": {
                    "type": "localfs",
                    "localfs": {
                        "dir": "/tmp/nydus"
                    }
                },
                "cache": {
                    "type": "fanotify",
                    "fanotify": {
                        "work_dir": "/tmp/nydus"
                    }
                },
                "metadata_path": "RAFS_V5"
            }
          }"#;
        let content = config
            .replace("/tmp/nydus", tmpdir.path().to_str().unwrap())
            .replace("RAFS_V5", &source_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());
        entry.blob_config.as_mut().unwrap().metadata_source = METADATA_SOURCE;

        let mgr = BlobCacheMgr::new();
        mgr.add_blob_entry(&entry).unwrap();

        entry.blob_id = "rafs-v6-cloned".to_string();
        mgr.add_blob_entry(&entry).unwrap();

        entry.domain_id = "domain3".to_string();
        entry.blob_id = "rafs-v6-domain3".to_string();
        mgr.add_blob_entry(&entry).unwrap();

        assert_eq!(mgr.get_state().id_to_config_map.len(), 5);

        mgr.remove_blob_entry(&BlobCacheObjectId {
            domain_id: "domain2".to_string(),
            blob_id: String::new(),
        })
        .unwrap();

        assert_eq!(mgr.get_state().id_to_config_map.len(), 2);
        assert!(mgr.get_config("domain2/rafs-v6").is_none());
        assert!(mgr.get_config("domain2/rafs-v6-cloned").is_none());
        assert!(
            mgr.get_config(
                "domain2/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef"
            )
            .is_none()
        );
        assert!(mgr.get_config("domain3/rafs-v6-domain3").is_some());
        assert!(
            mgr.get_config(
                "domain3/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef"
            )
            .is_some()
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support io_uring")]
    fn test_meta_blob() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");

        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let meta_blob = compio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(MetaBlob::new(&source_path))
                    .unwrap();
                assert_eq!(meta_blob.size(), 5 * EROFS_BLOCK_SIZE_4096);
                let buf = vec![0u8; 4096];
                let (res, buf) = meta_blob.async_read(0, buf).await;
                assert_eq!(res.unwrap(), 4096);
                assert_eq!(buf[0], 0);
                assert_eq!(buf[1023], 0);
                assert_eq!(buf[1024], 0xe2);
                assert_eq!(buf[1027], 0xe0);
                let (res, _buf) = meta_blob.async_read(0x6000, buf).await;
                assert_eq!(res.unwrap(), 0);
            });
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support io_uring")]
    fn test_meta_blob_file() {
        use std::os::fd::AsRawFd;

        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");

        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let meta_blob = compio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(MetaBlob::new(&source_path))
                    .unwrap();
                let file = meta_blob.file();
                assert!(file.as_raw_fd() >= 0);
            });
    }

    /// Helper to create a DataBlob from the test fixture bootstrap.
    /// Returns (DataBlob, TempDir) — TempDir must be kept alive.
    fn create_data_blob() -> (DataBlob, TempDir) {
        create_data_blob_with("filecache")
    }

    const FIXTURE_BLOB: &str = "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef";
    const FIXTURE_BOOT: &str = "rafs-v6-2.2.boot";
    /// Sixteen files of sizes ending at, inside and past 4K and 16K page boundaries, one chunk
    /// each, in one blob.
    const SMALL_FILES_BLOB: &str =
        "b0101724e1204f4956d532826eed5003a241e1f0e8e03934bafb76354044fffb";
    const SMALL_FILES_BOOT: &str = "rafs-v6-small-files.boot";

    /// [create_data_blob] with a cache of type `cache_type`.
    fn create_data_blob_with(cache_type: &str) -> (DataBlob, TempDir) {
        create_fixture_blob(cache_type, FIXTURE_BLOB, FIXTURE_BOOT)
    }

    /// The data blob `blob_id` of the fixture bootstrap `boot`, in a cache of type `cache_type`.
    fn create_fixture_blob(cache_type: &str, blob_id: &str, boot: &str) -> (DataBlob, TempDir) {
        use std::os::fd::AsRawFd;

        let tmp_dir = TempDir::new().unwrap();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");

        // Copy blob file to tmpdir
        let blob_src = PathBuf::from(root_dir)
            .join("../tests/texture/blobs")
            .join(blob_id);
        std::fs::copy(&blob_src, tmp_dir.path().join(blob_id)).unwrap();

        let boot_path = PathBuf::from(root_dir)
            .join("../tests/texture/bootstrap")
            .join(boot);

        let config = r#"
        {
            "type": "bootstrap",
            "id": "rafs-v6",
            "domain_id": "domain-test",
            "config_v2": {
                "version": 2,
                "id": "factory1",
                "backend": {
                    "type": "localfs",
                    "localfs": { "dir": "/tmp/nydus" }
                },
                "cache": { CACHE_SECTION },
                "metadata_path": "BOOT_PATH"
            }
        }"#;
        let content = config
            // A fanotify cache reads its work dir from the file cache section, which the v1
            // configuration form fills in.
            .replace(
                "CACHE_SECTION",
                &match cache_type {
                    "fanotify" => r#""type": "fanotify", "fanotify": { "work_dir": "/tmp/nydus" },
                        "filecache": { "work_dir": "/tmp/nydus" }"#
                        .to_string(),
                    t => format!(r#""type": "{t}", "{t}": {{ "work_dir": "/tmp/nydus" }}"#),
                },
            )
            .replace("/tmp/nydus", tmp_dir.path().to_str().unwrap())
            .replace("BOOT_PATH", &boot_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());

        let mgr = BlobCacheMgr::new();
        mgr.add_blob_entry(&entry).unwrap();

        let blob_key = generate_blob_key("domain-test", blob_id);
        let blob_config = mgr.get_config(&blob_key).unwrap();
        let data_blob_config = match blob_config {
            BlobConfig::DataBlob(c) => c,
            _ => panic!("expected DataBlob config"),
        };

        let data_blob = compio::runtime::Runtime::new()
            .unwrap()
            .block_on(DataBlob::new(&data_blob_config))
            .unwrap();
        assert!(data_blob.file().as_raw_fd() >= 0);
        (data_blob, tmp_dir)
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support copy_file_range")]
    fn test_data_blob_getters() {
        use std::os::fd::AsRawFd;

        let (data_blob, _tmp_dir) = create_data_blob();

        assert!(data_blob.file().as_raw_fd() >= 0);
        assert!(!data_blob.blob_info().blob_id().is_empty());
        // blob() returns the BlobCache reference
        let _ = data_blob.blob();
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support copy_file_range")]
    fn test_data_blob_async_fetch_zero_len() {
        let (data_blob, _tmp_dir) = create_data_blob();
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                // len=0 should short-circuit with Ok(())
                let res = data_blob.async_fetch(0, 0).await;
                assert!(res.is_ok());
            });
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support copy_file_range")]
    fn test_data_blob_async_fetch_and_read() {
        let (data_blob, _tmp_dir) = create_data_blob();
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                // Normal fetch
                let res = data_blob.async_fetch(0, 4096).await;
                assert!(res.is_ok());

                // Read after fetch
                let buf = vec![0u8; 4096];
                let (res, buf) = data_blob.async_read(0, buf).await;
                assert_eq!(res.unwrap(), 4096);
                // Verify we got actual data (not all zeros)
                assert!(buf.iter().any(|&b| b != 0));
            });
    }

    /// The fixture bootstrap's digest table for the fixture blob.
    fn fixture_digests() -> Vec<Option<nydus_storage::device::ChunkDigestEntry>> {
        boot_digests(FIXTURE_BOOT)
    }

    /// The digest table of the fixture bootstrap `boot` for its only blob.
    fn boot_digests(boot: &str) -> Vec<Option<nydus_storage::device::ChunkDigestEntry>> {
        let root_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let boot = PathBuf::from(root_dir)
            .join("../tests/texture/bootstrap")
            .join(boot);
        let (rs, _) =
            RafsSuper::load_from_file(&boot, Arc::new(ConfigV2::default()), false).unwrap();
        let mut tables = nydus_rafs::metadata::kernel_layout::chunk_digest_tables(&rs).unwrap();
        assert_eq!(tables.len(), 1);
        tables.remove(0)
    }

    fn is_ready(blob: &DataBlob, index: u32) -> bool {
        let chunk = blob.blob().get_chunk_info(index).unwrap();
        blob.blob()
            .get_chunk_map()
            .is_ready(chunk.as_ref())
            .unwrap()
    }

    /// A fanotify cache fills nothing it cannot validate, validates against the bootstrap's
    /// chunk table even though the blob meta carries no digests, and never marks a chunk that
    /// fails validation ready.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support copy_file_range")]
    fn fanotify_fills_are_validated_against_the_bootstrap() {
        use nydus_storage::device::BlobFeatures;

        let (blob, _tmp) = create_data_blob_with("fanotify");
        // The fixture's blob meta inlines chunk digests, but a fanotify cache never loads them:
        // it has only the bootstrap's, as for zran and tar-ref blobs, which inline none.
        assert!(
            blob.blob_info()
                .has_feature(BlobFeatures::INLINED_CHUNK_DIGEST)
        );
        let meta = blob.blob().get_blob_meta_info().unwrap().unwrap();
        assert!(meta.get_chunk_digest(0).is_none());
        let obj = blob.blob().get_blob_object().unwrap();
        let first = blob.blob().get_chunk_info(0).unwrap();
        let len = first.uncompressed_size() as u64;

        // Before any bootstrap supplied digests, there is nothing to validate against.
        assert!(obj.fetch_range_uncompressed(0, len).is_err());
        assert!(!is_ready(&blob, 0));

        // A digest that does not match the data: the fill fails and the chunk stays unready.
        let digests = fixture_digests();
        let mut wrong = digests.clone();
        wrong[0].as_mut().unwrap().digest.data[0] ^= 1;
        blob.blob().add_chunk_digests(&wrong).unwrap();
        let err = obj.fetch_range_uncompressed(0, len).unwrap_err();
        assert!(format!("{err:?}").contains("digest value"), "{err:?}");
        assert!(!is_ready(&blob, 0));

        // The chunk was never cached, so the wrong digest binds nothing: a bootstrap with the
        // right one replaces it.
        blob.blob().add_chunk_digests(&digests).unwrap();
        obj.fetch_range_uncompressed(0, len).unwrap();
        assert!(is_ready(&blob, 0));
        // Now the cached chunk binds its digest: a bootstrap that disagrees is refused.
        assert!(blob.blob().add_chunk_digests(&wrong).is_err());

        let (blob, _tmp) = create_data_blob_with("fanotify");
        let obj = blob.blob().get_blob_object().unwrap();
        // So is one whose chunk extent disagrees with the blob meta, once that is loaded.
        blob.blob().get_blob_meta_info().unwrap().unwrap();
        let mut moved = digests.clone();
        moved[0].as_mut().unwrap().uncompressed_offset += 1;
        assert!(blob.blob().add_chunk_digests(&moved).is_err());
        blob.blob().add_chunk_digests(&digests).unwrap();
        obj.fetch_range_uncompressed(0, len).unwrap();
        assert!(is_ready(&blob, 0));
    }

    /// A fresh cache serves only validated data from the start; one with ready chunks does once
    /// they are verified, and stops when its file is written by anything but a validating fill.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support copy_file_range")]
    fn served_data_is_verified_from_a_fresh_cache_on() {
        use std::os::unix::fs::FileExt;

        let (blob, _tmp) = create_data_blob_with("fanotify");
        let obj = blob.blob().get_blob_object().unwrap();
        blob.blob().add_chunk_digests(&fixture_digests()).unwrap();
        assert!(obj.is_served_data_verified());
        assert!(!obj.is_data_verified());

        let first = blob.blob().get_chunk_info(0).unwrap();
        obj.fetch_range_uncompressed(0, first.uncompressed_size() as u64)
            .unwrap();
        assert!(
            !obj.is_served_data_verified(),
            "a ready chunk nobody checked yet"
        );
        assert!(
            obj.verify_ready_chunks(&|| false, &mut |_| Ok(true))
                .unwrap()
        );
        assert!(obj.is_served_data_verified());
        let size = blob.blob_info().uncompressed_size();
        obj.fetch_range_uncompressed(0, size).unwrap();
        assert!(obj.is_served_data_verified(), "validated fills keep it");

        // SAFETY: the descriptor is the blob object's open cache file, borrowed for the write.
        let cache = std::mem::ManuallyDrop::new(unsafe {
            <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(obj.as_raw_fd())
        });
        cache
            .write_all_at(&[0], first.uncompressed_offset())
            .unwrap();
        assert!(!obj.is_served_data_verified());
    }

    /// The one-time check of chunks already marked ready records a clean cache file as
    /// verified, and hands a corrupted chunk to its caller to revoke, after which the next fill
    /// restores it.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support copy_file_range")]
    fn ready_chunks_are_verified_once() {
        use std::os::unix::fs::FileExt;

        let (blob, _tmp) = create_data_blob_with("fanotify");
        let obj = blob.blob().get_blob_object().unwrap();
        blob.blob().add_chunk_digests(&fixture_digests()).unwrap();
        let size = blob.blob_info().uncompressed_size();
        obj.fetch_range_uncompressed(0, size).unwrap();
        assert!(obj.is_all_data_ready());
        assert!(!obj.is_data_verified());

        let mut revoked = Vec::new();
        assert!(
            obj.verify_ready_chunks(&|| false, &mut |c| {
                revoked.push(c.id());
                Ok(true)
            })
            .unwrap()
        );
        assert!(revoked.is_empty());
        assert!(obj.is_data_verified());

        let first = blob.blob().get_chunk_info(0).unwrap();
        // SAFETY: the descriptor is the blob object's open cache file, borrowed for the write.
        let cache = std::mem::ManuallyDrop::new(unsafe {
            <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(obj.as_raw_fd())
        });
        let mut byte = [0u8; 1];
        cache
            .read_exact_at(&mut byte, first.uncompressed_offset())
            .unwrap();
        cache
            .write_all_at(&[byte[0] ^ 0xff], first.uncompressed_offset())
            .unwrap();
        // Written by something other than a validating fill, as an older release would.
        assert!(!obj.is_data_verified());

        // A chunk its caller cannot revoke is reported, left in place, and keeps the file
        // unverified; the check goes on past it.
        assert!(
            !obj.verify_ready_chunks(&|| false, &mut |c| {
                revoked.push(c.id());
                Ok(false)
            })
            .unwrap()
        );
        assert_eq!(revoked, vec![first.id()]);
        assert!(is_ready(&blob, first.id()));
        assert!(!obj.is_data_verified());

        revoked.clear();
        assert!(
            obj.verify_ready_chunks(&|| false, &mut |c| {
                revoked.push(c.id());
                obj.revoke_chunk(c.id()).map(|()| true)
            })
            .unwrap()
        );
        assert_eq!(revoked, vec![first.id()]);
        assert!(!is_ready(&blob, first.id()));
        assert!(obj.is_data_verified());

        obj.fetch_range_uncompressed(0, first.uncompressed_size() as u64)
            .unwrap();
        let mut again = [0u8; 1];
        cache
            .read_exact_at(&mut again, first.uncompressed_offset())
            .unwrap();
        assert_eq!(again, byte);

        // A stop request ends the check without recording anything.
        let (blob, _tmp) = create_data_blob_with("fanotify");
        let obj = blob.blob().get_blob_object().unwrap();
        blob.blob().add_chunk_digests(&fixture_digests()).unwrap();
        assert!(
            !obj.verify_ready_chunks(&|| true, &mut |_| Ok(true))
                .unwrap()
        );
        assert!(!obj.is_data_verified());

        // A ready chunk no bootstrap of this daemon references is left alone, and is no reason
        // to keep the file unverified: no file data is ever read from it.
        let (blob, _tmp) = create_data_blob_with("fanotify");
        let obj = blob.blob().get_blob_object().unwrap();
        let mut digests = fixture_digests();
        assert!(digests.len() > 1);
        digests[1] = None;
        blob.blob().add_chunk_digests(&digests).unwrap();
        let second = blob.blob().get_chunk_info(1).unwrap();
        blob.blob()
            .get_chunk_map()
            .set_ready_and_clear_pending(second.as_ref())
            .unwrap();
        assert!(
            obj.verify_ready_chunks(&|| false, &mut |_| panic!("not a mismatch"))
                .unwrap()
        );
        assert!(is_ready(&blob, 1));
        assert!(obj.is_data_verified());
    }

    /// Pre-content event ranges as the kernel raises them for host pages of 4K, 16K and 64K and
    /// for readahead windows, over a blob whose bootstrap leaves chunks unreferenced between
    /// referenced ones (the dead chunks of a layer whose files an upper layer replaced): every
    /// range covering referenced data is served, referenced chunks are filled and validated,
    /// unreferenced ones stay holes, and a referenced chunk failing validation is still refused.
    #[test]
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore = "Miri does not support copy_file_range")]
    fn event_ranges_of_every_page_size_leave_unreferenced_chunks_alone() {
        use std::os::unix::fs::FileExt;

        let full = boot_digests(SMALL_FILES_BOOT);
        let unreferenced = |i: usize| i % 3 == 1;
        let digests: Vec<_> = full
            .iter()
            .enumerate()
            .map(|(i, d)| if unreferenced(i) { None } else { *d })
            .collect();
        let fixture = || create_fixture_blob("fanotify", SMALL_FILES_BLOB, SMALL_FILES_BOOT);
        let (probe, _tmp) = fixture();
        let size = probe.blob_info().uncompressed_size();
        let extents: Vec<(u64, u64)> = (0..full.len() as u32)
            .map(|i| {
                let c = probe.blob().get_chunk_info(i).unwrap();
                (c.uncompressed_offset(), c.uncompressed_end())
            })
            .collect();
        let overlaps = |i: usize, start: u64, end: u64| extents[i].0 < end && extents[i].1 > start;
        // The fixture covers what large pages do differently: an unreferenced chunk shares a
        // 16K page with a referenced one, and a chunk ends inside a 4K page.
        assert!((0..extents.len()).any(|i| unreferenced(i)
            && (0..extents.len()).any(|j| !unreferenced(j)
                && overlaps(j, extents[i].0 & !0x3fff, (extents[i].1 + 0x3fff) & !0x3fff))));
        assert!(extents.iter().any(|&(_, end)| end % 4096 != 0));
        // The referenced chunk whose digest the corrupt runs get wrong.
        let victim = 2;
        assert!(!unreferenced(victim));

        for window in [4096u64, 16384, 65536, 128 << 10, 512 << 10] {
            for corrupt in [false, true] {
                let (blob, _tmp) = fixture();
                let obj = blob.blob().get_blob_object().unwrap();
                let mut table = digests.clone();
                if corrupt {
                    table[victim].as_mut().unwrap().digest.data[0] ^= 1;
                }
                blob.blob().add_chunk_digests(&table).unwrap();
                // Ranges start on window boundaries, the last ones past the blob's end.
                for start in (0..size + 2 * window).step_by(window as usize) {
                    let end = start + window;
                    // The kernel raises events only for reads of file data, which lies in
                    // referenced chunks.
                    if !(0..extents.len()).any(|i| !unreferenced(i) && overlaps(i, start, end)) {
                        continue;
                    }
                    let Some(count) = crate::fanotify::fill_count(start, window, size) else {
                        continue;
                    };
                    let served = obj.fetch_range_uncompressed(start, count);
                    if corrupt && overlaps(victim, start, start + count) {
                        assert!(served.is_err(), "window {window:#x} at {start:#x}");
                    } else if !corrupt {
                        served.unwrap_or_else(|e| panic!("window {window:#x} at {start:#x}: {e}"));
                    }
                }
                let cache = blob.blob().get_blob_object().unwrap();
                // SAFETY: the descriptor is the blob object's open cache file, borrowed here.
                let file = std::mem::ManuallyDrop::new(unsafe {
                    <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(cache.as_raw_fd())
                });
                for (i, &(start, end)) in extents.iter().enumerate() {
                    if unreferenced(i) {
                        assert!(!is_ready(&blob, i as u32), "window {window:#x} chunk {i}");
                        let mut bytes = vec![0xffu8; (end - start) as usize];
                        let n = file.read_at(&mut bytes, start).unwrap();
                        assert!(bytes[..n].iter().all(|&b| b == 0), "chunk {i} was filled");
                    } else if corrupt && i == victim {
                        assert!(!is_ready(&blob, i as u32), "window {window:#x}");
                    } else if !corrupt {
                        assert!(is_ready(&blob, i as u32), "window {window:#x} chunk {i}");
                    }
                }
                if !corrupt {
                    assert!(
                        obj.verify_ready_chunks(&|| false, &mut |c| panic!("chunk {}", c.id()))
                            .unwrap()
                    );
                    assert!(obj.is_data_verified());
                }
            }
        }
    }
}
