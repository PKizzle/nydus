// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Registry authentication: bearer challenges, token fetching, scopes, and
//! docker `config.json` credential loading.
//!
//! # The bearer / WWW-Authenticate dance
//!
//! Registries protected by a token service answer unauthenticated requests
//! with `401 Unauthorized` and a header like:
//!
//! ```text
//! WWW-Authenticate: Bearer realm="https://auth.example/token",service="registry.example",scope="repository:team/app:pull"
//! ```
//!
//! The client then GETs `realm?service=...&scope=...` (with basic auth when
//! credentials are available), receives a JSON body carrying `token` (or
//! `access_token`), and retries the original request with
//! `Authorization: Bearer <token>`. Tokens are scoped, so pull-only tokens
//! cannot authorize uploads — push operations request
//! `repository:<repo>:pull,push` (see [`push_scope`]). This module ports the
//! proven implementation from the snapshotter's referrer client.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::header::{ACCEPT, AUTHORIZATION, HeaderValue};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Explicit registry credentials (HTTP basic auth / token-service login).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    /// Registry user name.
    pub username: String,
    /// Registry password or access token.
    pub password: String,
}

impl Credentials {
    /// Encode as the base64 `user:password` payload of a basic-auth header
    /// (without the `Basic ` prefix; [`auth_header_value`] adds it).
    pub fn to_base64(&self) -> String {
        BASE64.encode(format!("{}:{}", self.username, self.password))
    }
}

/// A parsed `WWW-Authenticate: Bearer ...` challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BearerChallenge {
    /// Token endpoint URL.
    pub realm: String,
    /// Value for the `service=` query parameter, if the challenge names one.
    pub service: Option<String>,
    /// Scope the registry asks for, if the challenge names one. When present
    /// it is authoritative (e.g. a cross-repo mount challenge lists both
    /// repositories).
    pub scope: Option<String>,
}

/// Build the token scope for read-only access to `repo`.
pub fn pull_scope(repo: &str) -> String {
    format!("repository:{repo}:pull")
}

/// Build the token scope for upload access to `repo` (uploads also need pull
/// for the HEAD-dedup probe and for registries that verify layer existence).
pub fn push_scope(repo: &str) -> String {
    format!("repository:{repo}:pull,push")
}

/// Build the token scope for mounting a blob into `repo` from `from_repo`
/// (`POST /v2/<repo>/blobs/uploads/?mount=...&from=...` needs push on the
/// target and pull on the source).
pub fn mount_scope(repo: &str, from_repo: &str) -> String {
    format!("repository:{repo}:pull,push repository:{from_repo}:pull")
}

/// Small per-client bearer token cache, keyed by scope.
///
/// A [`RegistryClient`](crate::RegistryClient) is bound to a single registry
/// and a scope embeds the repository and the actions, so a scope key is
/// exactly the "registry + repo + actions" granularity tokens are issued at.
#[derive(Debug, Default)]
pub struct TokenCache {
    map: HashMap<String, String>,
}

impl TokenCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a cached token for `scope`.
    pub fn get(&self, scope: &str) -> Option<&str> {
        self.map.get(scope).map(String::as_str)
    }

    /// Cache `token` under `scope`, replacing any previous token.
    pub fn insert(&mut self, scope: &str, token: &str) {
        self.map.insert(scope.to_string(), token.to_string());
    }
}

/// Normalize a raw auth string into an `Authorization` header value: an
/// explicit `Basic ` / `Bearer ` prefix is preserved, anything else is treated
/// as a base64 `user:password` payload and gets the `Basic ` prefix.
pub fn auth_header_value(auth: &str) -> Result<HeaderValue> {
    let value = if auth.starts_with("Basic ") || auth.starts_with("Bearer ") {
        auth.to_string()
    } else {
        format!("Basic {auth}")
    };
    HeaderValue::from_str(&value).context("registry auth contained invalid header characters")
}

/// Parse a `WWW-Authenticate` header value into a [`BearerChallenge`].
/// Returns `None` for non-Bearer schemes (e.g. `Basic realm=...`) or a
/// challenge without a realm.
pub fn parse_bearer_challenge(value: &str) -> Option<BearerChallenge> {
    let value = value.trim();
    let params = value.strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in split_header_params(params) {
        let (key, raw_value) = part.split_once('=')?;
        let decoded = raw_value.trim().trim_matches('"').to_string();
        match key.trim() {
            "realm" => realm = Some(decoded),
            "service" => service = Some(decoded),
            "scope" => scope = Some(decoded),
            _ => {}
        }
    }
    Some(BearerChallenge {
        realm: realm?,
        service,
        scope,
    })
}

fn split_header_params(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    for (idx, ch) in value.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(value[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    out.push(value[start..].trim());
    out.into_iter().filter(|part| !part.is_empty()).collect()
}

/// Percent-encode a query-parameter value (RFC 3986 unreserved characters
/// pass through, everything else becomes `%XX`).
pub(crate) fn percent_encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct RegistryTokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

impl RegistryTokenResponse {
    fn into_token(self) -> Option<String> {
        self.token.or(self.access_token)
    }
}

/// Fetch a bearer token from `challenge.realm` for `scope`.
///
/// `basic_auth` is the base64 `user:password` payload (or a full
/// `Basic ...` / `Bearer ...` header value) forwarded to the token service so
/// it can mint an authenticated token; without it the token service issues an
/// anonymous token where allowed. `timeout` bounds the whole token request
/// (cyper has no client-level timeout, so it is applied per request via
/// `compio::time::timeout`).
pub async fn fetch_bearer_token(
    client: &cyper::Client,
    challenge: &BearerChallenge,
    scope: &str,
    basic_auth: Option<&str>,
    timeout: Option<Duration>,
) -> Result<String> {
    let mut url = challenge.realm.clone();
    let sep = if url.contains('?') { '&' } else { '?' };
    url.push(sep);
    if let Some(service) = challenge.service.as_deref() {
        url.push_str("service=");
        url.push_str(&percent_encode_query(service));
        url.push('&');
    }
    url.push_str("scope=");
    url.push_str(&percent_encode_query(scope));

    let mut request = client
        .get(url)
        .context("invalid registry token URL")?
        .header(ACCEPT, "application/json")
        .context("invalid Accept header")?;
    if let Some(auth) = basic_auth.map(auth_header_value).transpose()? {
        request = request
            .header(AUTHORIZATION, auth)
            .context("invalid Authorization header")?;
    }
    let send = request.send();
    let response = match timeout {
        Some(duration) => compio::time::timeout(duration, send)
            .await
            .map_err(|_| anyhow!("registry token request timed out"))?,
        None => send.await,
    }
    .context("registry token request failed")?;
    if !response.status().is_success() {
        bail!(
            "registry token request failed with HTTP {}",
            response.status()
        );
    }
    response
        .json::<RegistryTokenResponse>()
        .await
        .context("failed to decode registry token response")?
        .into_token()
        .context("registry token response did not include a token")
}

#[derive(Debug, Deserialize)]
struct DockerConfigFile {
    #[serde(default)]
    auths: HashMap<String, DockerConfigAuth>,
}

#[derive(Debug, Deserialize)]
struct DockerConfigAuth {
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// Load registry credentials for `host` from a docker `config.json`.
///
/// `path` selects an explicit config file; when `None` the default location
/// is used (`$DOCKER_CONFIG/config.json`, else `~/.docker/config.json`).
/// Returns the base64 `user:password` payload suitable for
/// [`auth_header_value`], or `None` when no matching entry exists (missing or
/// unparsable files are treated as "no credentials", never an error — this is
/// an optional input and explicit credentials always take precedence at the
/// [`RegistryClient`](crate::RegistryClient) level).
///
/// Docker Hub entries are stored under legacy keys, so for `docker.io` /
/// `registry-1.docker.io` the aliases `https://index.docker.io/v1/` and
/// `index.docker.io` are also consulted. Credential helpers
/// (`credHelpers` / `credsStore`) are not invoked.
pub fn docker_config_auth(path: Option<&Path>, host: &str) -> Option<String> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_docker_config_path()?,
    };
    let raw = std::fs::read(&path).ok()?;
    let config: DockerConfigFile = serde_json::from_slice(&raw).ok()?;
    for candidate in host_candidates(host) {
        if let Some(entry) = config.auths.get(&candidate)
            && let Some(auth) = entry_to_base64(entry)
        {
            return Some(auth);
        }
    }
    None
}

fn entry_to_base64(entry: &DockerConfigAuth) -> Option<String> {
    if let Some(auth) = entry.auth.as_deref()
        && !auth.is_empty()
    {
        return Some(auth.to_string());
    }
    match (entry.username.as_deref(), entry.password.as_deref()) {
        (Some(user), Some(pass)) => Some(BASE64.encode(format!("{user}:{pass}"))),
        _ => None,
    }
}

fn default_docker_config_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("DOCKER_CONFIG") {
        return Some(PathBuf::from(dir).join("config.json"));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".docker/config.json"))
}

/// Keys under which credentials for `host` may be stored in `config.json`.
fn host_candidates(host: &str) -> Vec<String> {
    let mut candidates = vec![
        host.to_string(),
        format!("https://{host}"),
        format!("http://{host}"),
    ];
    if host == "docker.io" || host == "registry-1.docker.io" || host == "index.docker.io" {
        candidates.extend(
            [
                "https://index.docker.io/v1/",
                "index.docker.io",
                "docker.io",
                "registry-1.docker.io",
            ]
            .map(str::to_string),
        );
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_challenge_parser_handles_quoted_params() {
        let parsed = parse_bearer_challenge(
            r#"Bearer realm="https://auth.local/token",service="registry.local",scope="repository:team/app:pull""#,
        )
        .unwrap();
        assert_eq!(parsed.realm, "https://auth.local/token");
        assert_eq!(parsed.service.as_deref(), Some("registry.local"));
        assert_eq!(parsed.scope.as_deref(), Some("repository:team/app:pull"));
    }

    #[test]
    fn bearer_challenge_parser_handles_push_scope() {
        // The challenge a registry sends for `POST /v2/<repo>/blobs/uploads/`.
        let parsed = parse_bearer_challenge(
            r#"Bearer realm="https://auth.local/token",service="registry.local",scope="repository:team/app:pull,push""#,
        )
        .unwrap();
        assert_eq!(
            parsed.scope.as_deref(),
            Some("repository:team/app:pull,push")
        );
    }

    #[test]
    fn bearer_challenge_parser_handles_mount_scope_with_comma_inside_quotes() {
        // Cross-repo mount: two space-separated scopes, plus a `,` inside the
        // quoted value which must NOT split the parameter list.
        let parsed = parse_bearer_challenge(
            r#"Bearer realm="https://auth.local/token",scope="repository:team/app:pull,push repository:team/base:pull""#,
        )
        .unwrap();
        assert_eq!(
            parsed.scope.as_deref(),
            Some("repository:team/app:pull,push repository:team/base:pull")
        );
    }

    #[test]
    fn bearer_challenge_parser_rejects_basic_and_missing_realm() {
        assert!(parse_bearer_challenge(r#"Basic realm="registry""#).is_none());
        assert!(parse_bearer_challenge(r#"Bearer service="registry""#).is_none());
    }

    #[test]
    fn scope_builders() {
        assert_eq!(pull_scope("team/app"), "repository:team/app:pull");
        assert_eq!(push_scope("team/app"), "repository:team/app:pull,push");
        assert_eq!(
            mount_scope("team/app", "team/base"),
            "repository:team/app:pull,push repository:team/base:pull"
        );
    }

    #[test]
    fn auth_header_preserves_explicit_scheme_or_adds_basic() {
        assert_eq!(auth_header_value("abc").unwrap(), "Basic abc");
        assert_eq!(auth_header_value("Bearer token").unwrap(), "Bearer token");
        assert_eq!(auth_header_value("Basic abc").unwrap(), "Basic abc");
    }

    #[test]
    fn percent_encoding_matches_referrer_client() {
        assert_eq!(
            percent_encode_query("repository:team/app:pull,push"),
            "repository%3Ateam%2Fapp%3Apull%2Cpush"
        );
    }

    #[test]
    fn token_cache_round_trip() {
        let mut cache = TokenCache::new();
        assert!(cache.get("repository:a:pull").is_none());
        cache.insert("repository:a:pull", "tok1");
        cache.insert("repository:a:pull,push", "tok2");
        assert_eq!(cache.get("repository:a:pull"), Some("tok1"));
        assert_eq!(cache.get("repository:a:pull,push"), Some("tok2"));
        cache.insert("repository:a:pull", "tok3");
        assert_eq!(cache.get("repository:a:pull"), Some("tok3"));
    }

    #[test]
    fn credentials_encode_to_basic_payload() {
        let creds = Credentials {
            username: "user".into(),
            password: "pass".into(),
        };
        assert_eq!(creds.to_base64(), BASE64.encode("user:pass"));
        assert_eq!(
            auth_header_value(&creds.to_base64()).unwrap(),
            format!("Basic {}", BASE64.encode("user:pass"))
        );
    }

    fn write_config(dir: &Path, json: &str) -> PathBuf {
        let path = dir.join("config.json");
        std::fs::write(&path, json).unwrap();
        path
    }

    #[test]
    fn docker_config_auth_field_and_host_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            r#"{"auths":{"registry.local:5000":{"auth":"dXNlcjpwYXNz"}}}"#,
        );
        assert_eq!(
            docker_config_auth(Some(&path), "registry.local:5000").as_deref(),
            Some("dXNlcjpwYXNz")
        );
        assert!(docker_config_auth(Some(&path), "other.registry").is_none());
    }

    #[test]
    fn docker_config_username_password_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            r#"{"auths":{"ghcr.io":{"username":"user","password":"pass"}}}"#,
        );
        assert_eq!(
            docker_config_auth(Some(&path), "ghcr.io"),
            Some(BASE64.encode("user:pass"))
        );
    }

    #[test]
    fn docker_config_docker_io_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            r#"{"auths":{"https://index.docker.io/v1/":{"auth":"aHVi"}}}"#,
        );
        // Both the logical host and the API host resolve the legacy hub key.
        assert_eq!(
            docker_config_auth(Some(&path), "docker.io").as_deref(),
            Some("aHVi")
        );
        assert_eq!(
            docker_config_auth(Some(&path), "registry-1.docker.io").as_deref(),
            Some("aHVi")
        );
    }

    #[test]
    fn docker_config_missing_or_invalid_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert!(docker_config_auth(Some(&missing), "ghcr.io").is_none());
        let invalid = write_config(dir.path(), "not json");
        assert!(docker_config_auth(Some(&invalid), "ghcr.io").is_none());
    }
}
