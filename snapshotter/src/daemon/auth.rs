// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Registry authentication provider chain.
//!
//! Kubernetes does **not** normally make `imagePullSecrets` available by files
//! on disk for remote snapshotters to read. The intended kubelet flow is:
//! imagePullSecrets / kubelet credential-provider plugins → CRI PullImage auth
//! → container runtime. Because remote snapshotters are outside that handoff,
//! we expose a small runtime auth store that a CRI helper / credential-provider
//! bridge can populate. This module deliberately never reads Docker config or
//! Kubernetes Secret files directly.

use crate::config::SnapshotterConfig;
use crate::daemon::image_ref::ImageRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static RUNTIME_AUTH: OnceLock<Mutex<RuntimeAuthStore>> = OnceLock::new();

#[derive(Default)]
struct RuntimeAuthStore {
    entries: HashMap<String, RuntimeAuthEntry>,
}

struct RuntimeAuthEntry {
    auth: String,
    expires_at: Option<SystemTime>,
}

/// Credential payload accepted by `/api/v1/auth`. `auth` is the Docker-style
/// base64 `user:password` value consumed by nydusd's registry backend.
#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeAuthRequest {
    pub registry: String,
    pub auth: String,
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
}

/// Non-secret runtime auth metadata returned by `/api/v1/auth`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeAuthRecord {
    pub registry: String,
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeAuthError {
    #[error("runtime auth store lock poisoned")]
    StorePoisoned,
}

/// Resolve registry auth for an image reference from runtime-injected
/// credentials only. The returned value is the Docker-compatible base64
/// `auth` payload expected by nydusd's registry backend.
pub fn resolve_auth(_config: &SnapshotterConfig, image_ref: &ImageRef) -> Option<String> {
    runtime_auth(image_ref)
}

pub fn set_runtime_auth(entries: Vec<RuntimeAuthRequest>) -> Result<usize, RuntimeAuthError> {
    let mut store = runtime_store()
        .lock()
        .map_err(|_| RuntimeAuthError::StorePoisoned)?;
    store.prune_expired(SystemTime::now());
    for entry in entries {
        if entry.auth.is_empty() || entry.registry.trim().is_empty() {
            continue;
        }
        let expires_at = entry
            .expires_in_seconds
            .map(|ttl| SystemTime::now() + Duration::from_secs(ttl));
        store.entries.insert(
            normalize_registry_key(&entry.registry),
            RuntimeAuthEntry {
                auth: entry.auth,
                expires_at,
            },
        );
    }
    Ok(store.entries.len())
}

pub fn runtime_auth_records() -> Result<Vec<RuntimeAuthRecord>, RuntimeAuthError> {
    let mut store = runtime_store()
        .lock()
        .map_err(|_| RuntimeAuthError::StorePoisoned)?;
    store.prune_expired(SystemTime::now());
    let mut records = store
        .entries
        .iter()
        .map(|(registry, entry)| RuntimeAuthRecord {
            registry: registry.clone(),
            expires_at_unix: entry.expires_at.and_then(system_time_secs),
        })
        .collect::<Vec<_>>();
    records.sort_by(|a, b| a.registry.cmp(&b.registry));
    Ok(records)
}

fn runtime_auth(image_ref: &ImageRef) -> Option<String> {
    let mut store = runtime_store().lock().ok()?;
    store.prune_expired(SystemTime::now());
    auth_candidates(image_ref)
        .into_iter()
        .find_map(|candidate| {
            store
                .entries
                .get(&candidate)
                .map(|entry| entry.auth.clone())
        })
}

fn auth_candidates(image_ref: &ImageRef) -> Vec<String> {
    let mut out = Vec::new();
    push_repo_scoped_candidates(&mut out, &image_ref.api_host, &image_ref.repo);
    push_repo_scoped_candidates(&mut out, &image_ref.host, &image_ref.repo);
    out.extend([
        image_ref.api_host.clone(),
        image_ref.host.clone(),
        format!("https://{}", image_ref.api_host),
        format!("https://{}", image_ref.host),
    ]);
    if image_ref.host == "docker.io" || image_ref.api_host == "registry-1.docker.io" {
        out.push("https://index.docker.io/v1/".to_string());
    }
    out = out
        .into_iter()
        .map(|candidate| normalize_registry_key(&candidate))
        .collect();
    dedup_preserve_order(out)
}

fn push_repo_scoped_candidates(out: &mut Vec<String>, host: &str, repo: &str) {
    let mut parts = repo
        .split('/')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    while !parts.is_empty() {
        out.push(format!("{host}/{}", parts.join("/")));
        parts.pop();
    }
}

fn dedup_preserve_order(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

fn normalize_registry_key(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string()
}

fn runtime_store() -> &'static Mutex<RuntimeAuthStore> {
    RUNTIME_AUTH.get_or_init(|| Mutex::new(RuntimeAuthStore::default()))
}

impl RuntimeAuthStore {
    fn prune_expired(&mut self, now: SystemTime) {
        self.entries
            .retain(|_, entry| entry.expires_at.map(|t| t > now).unwrap_or(true));
    }
}

fn system_time_secs(t: SystemTime) -> Option<u64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::image_ref::parse_image_ref;

    #[test]
    fn runtime_auth_store_takes_precedence() {
        let image = parse_image_ref("registry.runtime/team/app:1").unwrap();
        let before = runtime_auth_records().unwrap().len();
        let count = set_runtime_auth(vec![RuntimeAuthRequest {
            registry: "https://registry.runtime".to_string(),
            auth: "runtime-auth".to_string(),
            expires_in_seconds: Some(60),
        }])
        .unwrap();
        assert!(count >= before);
        assert_eq!(runtime_auth(&image).as_deref(), Some("runtime-auth"));
        assert!(
            runtime_auth_records()
                .unwrap()
                .iter()
                .any(|record| record.registry == "registry.runtime")
        );
    }

    #[test]
    fn auth_candidates_include_host_variants() {
        let image = parse_image_ref("docker.io/library/nginx:latest").unwrap();
        let candidates = auth_candidates(&image);
        assert!(candidates.contains(&"docker.io/library/nginx".to_string()));
        assert!(candidates.contains(&"docker.io/library".to_string()));
        assert!(candidates.contains(&"docker.io".to_string()));
        assert!(candidates.contains(&"registry-1.docker.io".to_string()));
        assert!(candidates.contains(&"index.docker.io/v1".to_string()));
    }

    #[test]
    fn runtime_auth_matches_repository_scoped_keys_before_host_keys() {
        let image = parse_image_ref("registry.scoped/team/app:1").unwrap();
        set_runtime_auth(vec![
            RuntimeAuthRequest {
                registry: "registry.scoped".to_string(),
                auth: "host-auth".to_string(),
                expires_in_seconds: Some(60),
            },
            RuntimeAuthRequest {
                registry: "registry.scoped/team/app".to_string(),
                auth: "repo-auth".to_string(),
                expires_in_seconds: Some(60),
            },
        ])
        .unwrap();

        assert_eq!(runtime_auth(&image).as_deref(), Some("repo-auth"));
    }

    #[test]
    fn resolve_auth_ignores_absent_runtime_credentials() {
        let image = parse_image_ref("registry.noauth/team/app:1").unwrap();
        assert!(resolve_auth(&SnapshotterConfig::default(), &image).is_none());
    }
}
