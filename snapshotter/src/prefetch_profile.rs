// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Workload-profile prefetch model.
//!
//! This is the phase-3 foundation for profile-guided prefetch landmarks: NRI,
//! fanotify tracing, or offline tools can all normalize access records into a
//! stable ordered file list before the builder embeds it into RAFS metadata.

use crate::nri::AccessProfileRecord;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tracing::warn;

pub const PREFETCH_PROFILE_VERSION: u32 = 1;

static RUNTIME_PREFETCH: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchProfile {
    pub version: u32,
    pub image: String,
    pub files: Vec<PrefetchProfileEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchProfileEntry {
    pub path: String,
    pub first_seen_unix: u64,
    pub hits: u64,
}

/// Persistent on-disk store for profile-guided prefetch data.
#[derive(Clone, Debug)]
pub struct PrefetchProfileStore {
    root: PathBuf,
}

impl PrefetchProfileStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn from_cache_root(cache_root: &Path) -> Self {
        let state_root = cache_root.parent().unwrap_or(cache_root);
        Self::new(state_root.join("prefetch-profiles"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put(&self, profile: &PrefetchProfile) -> Result<PathBuf> {
        validate_profile(profile)?;
        fs::create_dir_all(&self.root).with_context(|| {
            format!(
                "failed to create prefetch profile directory {}",
                self.root.display()
            )
        })?;
        let path = self.profile_path(&profile.image);
        let encoded =
            serde_json::to_vec_pretty(profile).context("failed to encode prefetch profile")?;
        fs::write(&path, encoded)
            .with_context(|| format!("failed to persist prefetch profile {}", path.display()))?;
        Ok(path)
    }

    pub fn list(&self) -> Result<Vec<PrefetchProfile>> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "failed to read prefetch profile dir {}",
                        self.root.display()
                    )
                })
            }
        };
        let mut profiles = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            match fs::read(&path)
                .with_context(|| format!("failed to read prefetch profile {}", path.display()))
                .and_then(|bytes| {
                    serde_json::from_slice::<PrefetchProfile>(&bytes)
                        .context("failed to decode prefetch profile")
                }) {
                Ok(profile) => {
                    if let Err(e) = validate_profile(&profile) {
                        warn!(path = %path.display(), error = %e, "ignoring invalid prefetch profile");
                        continue;
                    }
                    profiles.push(profile);
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "ignoring unreadable prefetch profile")
                }
            }
        }
        profiles.sort_by(|a, b| a.image.cmp(&b.image));
        Ok(profiles)
    }

    pub fn restore_runtime(&self) -> Result<usize> {
        let profiles = self.list()?;
        let entries = profiles
            .iter()
            .map(|profile| (profile.image.clone(), profile.prefetch_files()))
            .collect::<Vec<_>>();
        set_runtime_prefetch(entries).context("failed to restore runtime prefetch profiles")
    }

    fn profile_path(&self, image: &str) -> PathBuf {
        self.root.join(format!("{}.json", profile_key(image)))
    }
}

impl PrefetchProfile {
    pub fn from_access_records(
        image: impl Into<String>,
        records: impl IntoIterator<Item = AccessProfileRecord>,
    ) -> Self {
        let mut entries = Vec::<PrefetchProfileEntry>::new();
        let mut index = HashMap::<String, usize>::new();

        for record in records {
            let Some(path) = normalize_prefetch_path(&record.path) else {
                continue;
            };
            if let Some(pos) = index.get(&path).copied() {
                entries[pos].hits = entries[pos].hits.saturating_add(1);
                entries[pos].first_seen_unix =
                    entries[pos].first_seen_unix.min(record.timestamp_unix);
            } else {
                index.insert(path.clone(), entries.len());
                entries.push(PrefetchProfileEntry {
                    path,
                    first_seen_unix: record.timestamp_unix,
                    hits: 1,
                });
            }
        }

        entries.sort_by_key(|entry| (entry.first_seen_unix, entry.path.clone()));
        Self {
            version: PREFETCH_PROFILE_VERSION,
            image: image.into(),
            files: entries,
        }
    }

    pub fn prefetch_files(&self) -> Vec<String> {
        normalize_prefetch_files(self.files.iter().map(|entry| entry.path.as_str()))
    }
}

pub fn normalize_prefetch_files<'a>(paths: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out = Vec::new();
    for path in paths {
        let Some(path) = normalize_prefetch_path(path) else {
            continue;
        };
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimePrefetchError {
    #[error("runtime prefetch store lock poisoned")]
    StorePoisoned,
}

pub fn set_runtime_prefetch(
    entries: impl IntoIterator<Item = (String, Vec<String>)>,
) -> Result<usize, RuntimePrefetchError> {
    let mut store = runtime_prefetch_store()
        .lock()
        .map_err(|_| RuntimePrefetchError::StorePoisoned)?;
    let mut updated = 0usize;
    for (image, files) in entries {
        if image.trim().is_empty() {
            continue;
        }
        let files = normalize_prefetch_files(files.iter().map(String::as_str));
        store.insert(image, files);
        updated += 1;
    }
    Ok(updated)
}

pub fn runtime_prefetch_records() -> Result<HashMap<String, Vec<String>>, RuntimePrefetchError> {
    runtime_prefetch_store()
        .lock()
        .map_err(|_| RuntimePrefetchError::StorePoisoned)
        .map(|store| store.clone())
}

pub fn runtime_prefetch_for_image(image: &str) -> Option<Vec<String>> {
    runtime_prefetch_store().lock().ok()?.get(image).cloned()
}

fn runtime_prefetch_store() -> &'static Mutex<HashMap<String, Vec<String>>> {
    RUNTIME_PREFETCH.get_or_init(|| Mutex::new(HashMap::new()))
}

fn normalize_prefetch_path(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() || !path.starts_with('/') || path.as_bytes().contains(&0) {
        return None;
    }

    let mut normalized = String::with_capacity(path.len());
    let mut previous_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !previous_slash {
                normalized.push(ch);
            }
            previous_slash = true;
        } else {
            normalized.push(ch);
            previous_slash = false;
        }
    }

    Some(normalized)
}

fn validate_profile(profile: &PrefetchProfile) -> Result<()> {
    if profile.version != PREFETCH_PROFILE_VERSION {
        bail!(
            "unsupported prefetch profile version {}; expected {}",
            profile.version,
            PREFETCH_PROFILE_VERSION
        );
    }
    if profile.image.trim().is_empty() {
        bail!("prefetch profile image must be non-empty");
    }
    if profile.prefetch_files().is_empty() {
        bail!("prefetch profile must contain at least one absolute path");
    }
    Ok(())
}

fn profile_key(image: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(image.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(path: &str, timestamp_unix: u64) -> AccessProfileRecord {
        AccessProfileRecord {
            container_id: "ctr".to_string(),
            image: "registry.local/app:1".to_string(),
            path: path.to_string(),
            op: "open".to_string(),
            timestamp_unix,
        }
    }

    #[test]
    fn profile_preserves_first_access_order_and_counts_hits() {
        let profile = PrefetchProfile::from_access_records(
            "registry.local/app:1",
            [
                record("/lib/libc.so", 20),
                record(" /bin/app ", 10),
                record("/lib//libc.so", 30),
                record("relative", 5),
            ],
        );

        assert_eq!(profile.version, PREFETCH_PROFILE_VERSION);
        assert_eq!(profile.prefetch_files(), vec!["/bin/app", "/lib/libc.so"]);
        assert_eq!(profile.files[1].hits, 2);
        assert_eq!(profile.files[1].first_seen_unix, 20);
    }

    #[test]
    fn normalizes_prefetch_files_without_duplicates() {
        let files = normalize_prefetch_files(["/a", "/a", " /b//c ", "", "relative"]);
        assert_eq!(files, vec!["/a", "/b/c"]);
    }

    #[test]
    fn runtime_prefetch_store_normalizes_files() {
        let updated = set_runtime_prefetch([(
            "registry.local/runtime-prefetch:1".to_string(),
            vec!["/bin//app".to_string(), "relative".to_string()],
        )])
        .unwrap();
        assert_eq!(updated, 1);
        assert_eq!(
            runtime_prefetch_for_image("registry.local/runtime-prefetch:1"),
            Some(vec!["/bin/app".to_string()])
        );
    }

    #[test]
    fn profile_store_persists_and_restores_runtime_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = PrefetchProfileStore::new(dir.path().join("profiles"));
        let profile = PrefetchProfile::from_access_records(
            "registry.local/profile-store:1",
            [record("/bin/app", 1), record("/lib/libc.so", 2)],
        );

        let path = store.put(&profile).unwrap();
        assert!(path.exists());
        assert_eq!(store.list().unwrap(), vec![profile.clone()]);
        assert_eq!(store.restore_runtime().unwrap(), 1);
        assert_eq!(
            runtime_prefetch_for_image("registry.local/profile-store:1"),
            Some(vec!["/bin/app".to_string(), "/lib/libc.so".to_string()])
        );
    }

    #[test]
    fn profile_store_rejects_invalid_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let store = PrefetchProfileStore::new(dir.path());
        let profile = PrefetchProfile {
            version: PREFETCH_PROFILE_VERSION,
            image: "".to_string(),
            files: Vec::new(),
        };
        assert!(store.put(&profile).is_err());
    }
}
