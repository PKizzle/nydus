// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! NRI integration primitives.
//!
//! This module contains the stable request/record model shared by the NRI
//! plugin binaries, the native ttrpc transport, and the sysctl
//! `/api/v1/prefetch` endpoint.

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::prefetch_profile::PrefetchProfile;

pub const DEFAULT_SYSCTL_SOCKET: &str = "/run/containerd-nydus/containerd-nydus-api.sock";
pub const NYDUS_PREFETCH_ANNOTATION: &str = "containerd.io/nydus-prefetch";

/// Prefetch hints delivered by an NRI plugin when a pod sandbox starts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchHint {
    pub image: String,
    pub files: Vec<String>,
}

impl PrefetchHint {
    pub fn from_newline_list(image: impl Into<String>, prefetch: &str) -> Self {
        Self {
            image: image.into(),
            files: prefetch
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(ToString::to_string)
                .collect(),
        }
    }

    pub fn from_profile(profile: &PrefetchProfile) -> Self {
        Self {
            image: profile.image.clone(),
            files: profile.prefetch_files(),
        }
    }
}

/// Extract a prefetch hint from NRI/container annotations.
pub fn prefetch_hint_from_annotations(
    image: impl Into<String>,
    annotations: &HashMap<String, String>,
) -> Option<PrefetchHint> {
    let prefetch = annotations.get(NYDUS_PREFETCH_ANNOTATION)?;
    let hint = PrefetchHint::from_newline_list(image, prefetch);
    (!hint.files.is_empty()).then_some(hint)
}

/// One optimizer access-profile event collected by an NRI optimizer plugin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccessProfileRecord {
    pub container_id: String,
    pub image: String,
    pub path: String,
    pub op: String,
    pub timestamp_unix: u64,
}

impl AccessProfileRecord {
    pub fn new(
        container_id: impl Into<String>,
        image: impl Into<String>,
        path: impl Into<String>,
        op: impl Into<String>,
    ) -> Self {
        Self {
            container_id: container_id.into(),
            image: image.into(),
            path: path.into(),
            op: op.into(),
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Minimal sysctl client shared by the Rust NRI plugin binaries.
#[derive(Clone, Debug)]
pub struct SysctlClient {
    socket: PathBuf,
}

impl SysctlClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn put_prefetch_hints(&self, hints: &[PrefetchHint]) -> Result<PrefetchUpdateResponse> {
        let entries = hints
            .iter()
            .map(|hint| PrefetchSysctlEntry {
                image: hint.image.clone(),
                prefetch: String::new(),
                files: hint.files.clone(),
            })
            .collect::<Vec<_>>();
        self.put_json("/api/v1/prefetch", &entries)
    }

    pub fn put_prefetch_profile(
        &self,
        profile: &PrefetchProfile,
    ) -> Result<PrefetchUpdateResponse> {
        self.put_json("/api/v1/prefetch/profile", profile)
    }

    fn put_json<T, R>(&self, path: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let body = serde_json::to_vec(body).context("failed to encode sysctl request")?;
        let request = format!(
            "PUT {path} HTTP/1.1\r\nHost: nydus-snapshotter\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let response = send_http_over_unix(&self.socket, request.as_bytes(), &body)?;
        parse_json_response(&response)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchUpdateResponse {
    pub images: usize,
}

#[derive(Clone, Debug, Serialize)]
struct PrefetchSysctlEntry {
    image: String,
    prefetch: String,
    files: Vec<String>,
}

fn send_http_over_unix(socket: &Path, headers: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket).with_context(|| {
        format!(
            "failed to connect to nydus sysctl socket {}",
            socket.display()
        )
    })?;
    stream
        .write_all(headers)
        .context("failed to write sysctl request headers")?;
    stream
        .write_all(body)
        .context("failed to write sysctl request body")?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .context("failed to read sysctl response")?;
    Ok(response)
}

fn parse_json_response<T: DeserializeOwned>(response: &[u8]) -> Result<T> {
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response from nydus sysctl")?;
    let headers = std::str::from_utf8(&response[..header_end])
        .context("HTTP response headers are not UTF-8")?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .context("missing HTTP status from nydus sysctl response")?;
    let body = &response[header_end + 4..];
    if !(200..300).contains(&status) {
        bail!(
            "nydus sysctl rejected NRI request with HTTP {status}: {}",
            String::from_utf8_lossy(body)
        );
    }
    serde_json::from_slice(body).context("failed to decode nydus sysctl response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefetch_hint_trims_empty_lines() {
        let hint = PrefetchHint::from_newline_list("image", "/bin/app\n\n /lib/libc.so \n");
        assert_eq!(
            hint.files,
            vec!["/bin/app".to_string(), "/lib/libc.so".to_string()]
        );
    }

    #[test]
    fn access_profile_record_captures_required_fields() {
        let record = AccessProfileRecord::new("ctr", "image", "/bin/app", "open");
        assert_eq!(record.container_id, "ctr");
        assert_eq!(record.image, "image");
        assert_eq!(record.path, "/bin/app");
        assert_eq!(record.op, "open");
    }

    #[test]
    fn prefetch_hint_can_be_built_from_profile() {
        let profile = PrefetchProfile::from_access_records(
            "image",
            [AccessProfileRecord {
                container_id: "ctr".to_string(),
                image: "image".to_string(),
                path: "/bin/app".to_string(),
                op: "open".to_string(),
                timestamp_unix: 1,
            }],
        );

        let hint = PrefetchHint::from_profile(&profile);
        assert_eq!(hint.image, "image");
        assert_eq!(hint.files, vec!["/bin/app"]);
    }

    #[test]
    fn prefetch_hint_from_annotations_uses_nydus_key() {
        let annotations = HashMap::from([(
            NYDUS_PREFETCH_ANNOTATION.to_string(),
            "/bin/app\n/lib/libc.so\n".to_string(),
        )]);
        let hint = prefetch_hint_from_annotations("image", &annotations).unwrap();
        assert_eq!(hint.image, "image");
        assert_eq!(hint.files, vec!["/bin/app", "/lib/libc.so"]);
    }

    #[test]
    fn prefetch_hint_from_annotations_ignores_missing_or_empty() {
        assert!(prefetch_hint_from_annotations("image", &HashMap::new()).is_none());
        let annotations =
            HashMap::from([(NYDUS_PREFETCH_ANNOTATION.to_string(), "\n".to_string())]);
        assert!(prefetch_hint_from_annotations("image", &annotations).is_none());
    }

    #[test]
    fn parse_json_response_accepts_successful_sysctl_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{\"images\":1}";
        let parsed: PrefetchUpdateResponse = parse_json_response(response).unwrap();
        assert_eq!(parsed.images, 1);
    }
}
