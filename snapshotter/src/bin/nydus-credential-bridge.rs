// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Small credential bridge for the Rust Nydus snapshotter.
//!
//! The bridge never reads Docker config files or Kubernetes Secret files. It
//! either accepts credential JSON on stdin or wraps a kubelet credential
//! provider executable, forwards stdin to that provider, injects the provider's
//! response into the Nydus runtime auth endpoint, and then writes the original
//! provider response back to stdout unchanged.

#![deny(warnings)]
#![warn(clippy::all)]

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

const DEFAULT_SYSCTL_SOCKET: &str = "/run/containerd-nydus/containerd-nydus-api.sock";
const DEFAULT_TTL_SECONDS: u64 = 300;

#[derive(Parser, Debug)]
#[command(
    name = "nydus-credential-bridge",
    about = "Inject runtime registry credentials into the Nydus snapshotter"
)]
struct Args {
    /// Nydus sysctl Unix socket used by /api/v1/auth.
    #[arg(long, default_value = DEFAULT_SYSCTL_SOCKET)]
    sysctl_socket: PathBuf,

    /// TTL applied when the input format has no cache duration.
    #[arg(long, default_value_t = DEFAULT_TTL_SECONDS)]
    default_ttl_seconds: u64,

    #[command(subcommand)]
    command: BridgeCommand,
}

#[derive(Subcommand, Debug)]
enum BridgeCommand {
    /// Read credential JSON from stdin and inject it into Nydus.
    Inject(InjectArgs),
    /// Wrap a kubelet credential-provider executable and tee its response to Nydus.
    Wrap(WrapArgs),
}

#[derive(Parser, Debug)]
struct InjectArgs {
    /// Input format. `auto` accepts native Nydus entries or kubelet CredentialProviderResponse.
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
}

#[derive(Parser, Debug)]
struct WrapArgs {
    /// Credential-provider executable to run.
    provider: PathBuf,

    /// Arguments passed to the provider executable.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    provider_args: Vec<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum InputFormat {
    Auto,
    Runtime,
    Kubelet,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RuntimeAuthEntry {
    registry: String,
    auth: String,
    #[serde(default)]
    expires_in_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RuntimeAuthEnvelope {
    credentials: Vec<RuntimeAuthEntry>,
}

#[derive(Debug, Deserialize)]
struct CredentialProviderResponse {
    #[serde(default, rename = "apiVersion")]
    api_version: String,
    #[serde(default)]
    kind: String,
    #[serde(default, rename = "cacheDuration")]
    cache_duration: Option<Value>,
    #[serde(default)]
    auth: HashMap<String, DockerAuthConfig>,
}

#[derive(Debug, Deserialize)]
struct DockerAuthConfig {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    auth: Option<String>,
    #[serde(default, rename = "identityToken")]
    identity_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    registries: usize,
}

#[derive(Debug, Serialize)]
struct InjectReport {
    injected_credentials: usize,
    cached_registries: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        BridgeCommand::Inject(inject) => {
            let input = read_stdin()?;
            let entries = extract_runtime_auth(&input, inject.format, args.default_ttl_seconds)?;
            let response = put_auth(&args.sysctl_socket, &entries)?;
            serde_json::to_writer_pretty(
                std::io::stdout(),
                &InjectReport {
                    injected_credentials: entries.len(),
                    cached_registries: response.registries,
                },
            )?;
            println!();
        }
        BridgeCommand::Wrap(wrap) => {
            let request = read_stdin()?;
            let provider_response = run_provider(&wrap.provider, &wrap.provider_args, &request)?;
            let entries = extract_runtime_auth(
                &provider_response,
                InputFormat::Kubelet,
                args.default_ttl_seconds,
            )?;
            if !entries.is_empty() {
                let response = put_auth(&args.sysctl_socket, &entries)?;
                eprintln!(
                    "injected {} credential scope(s) into nydus runtime auth ({} cached registry scope(s))",
                    entries.len(),
                    response.registries
                );
            }
            std::io::stdout().write_all(&provider_response)?;
        }
    }
    Ok(())
}

fn read_stdin() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("failed to read stdin")?;
    Ok(input)
}

fn run_provider(provider: &Path, args: &[String], stdin_payload: &[u8]) -> Result<Vec<u8>> {
    let mut child = ProcessCommand::new(provider)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn credential provider {}", provider.display()))?;

    child
        .stdin
        .take()
        .context("credential provider stdin was unavailable")?
        .write_all(stdin_payload)
        .context("failed to write kubelet request to credential provider")?;

    let output = child
        .wait_with_output()
        .context("failed to wait for credential provider")?;
    if !output.status.success() {
        std::io::stderr().write_all(&output.stderr).ok();
        bail!(
            "credential provider {} exited with {}",
            provider.display(),
            output.status
        );
    }
    Ok(output.stdout)
}

fn extract_runtime_auth(
    payload: &[u8],
    format: InputFormat,
    default_ttl_seconds: u64,
) -> Result<Vec<RuntimeAuthEntry>> {
    let value: Value = serde_json::from_slice(payload).context("credential payload is not JSON")?;
    match format {
        InputFormat::Runtime => runtime_entries_from_value(value),
        InputFormat::Kubelet => kubelet_entries_from_value(value, default_ttl_seconds),
        InputFormat::Auto => {
            if value.is_array() || value.get("credentials").is_some() {
                runtime_entries_from_value(value)
            } else if value.get("auth").is_some() {
                kubelet_entries_from_value(value, default_ttl_seconds)
            } else {
                bail!(
                    "unsupported credential payload; expected runtime entries or kubelet CredentialProviderResponse"
                )
            }
        }
    }
}

fn runtime_entries_from_value(value: Value) -> Result<Vec<RuntimeAuthEntry>> {
    let entries = if value.is_array() {
        serde_json::from_value::<Vec<RuntimeAuthEntry>>(value)
            .context("invalid native runtime auth array")?
    } else {
        serde_json::from_value::<RuntimeAuthEnvelope>(value)
            .context("invalid native runtime auth envelope")?
            .credentials
    };
    Ok(entries
        .into_iter()
        .filter(|entry| !entry.registry.trim().is_empty() && !entry.auth.is_empty())
        .collect())
}

fn kubelet_entries_from_value(
    value: Value,
    default_ttl_seconds: u64,
) -> Result<Vec<RuntimeAuthEntry>> {
    let response: CredentialProviderResponse =
        serde_json::from_value(value).context("invalid kubelet CredentialProviderResponse")?;
    if !response.kind.is_empty() && response.kind != "CredentialProviderResponse" {
        bail!(
            "unexpected kubelet credential response kind {}",
            response.kind
        );
    }
    if !response.api_version.is_empty()
        && !response
            .api_version
            .starts_with("credentialprovider.kubelet.k8s.io/")
    {
        bail!(
            "unexpected kubelet credential response apiVersion {}",
            response.api_version
        );
    }

    let ttl = response
        .cache_duration
        .as_ref()
        .and_then(parse_cache_duration_value)
        .unwrap_or(default_ttl_seconds);

    let mut entries = Vec::new();
    for (scope, auth_config) in response.auth {
        if scope.contains('*') {
            continue;
        }
        let Some(auth) = auth_config.to_registry_auth() else {
            continue;
        };
        entries.push(RuntimeAuthEntry {
            registry: normalize_registry_scope(&scope),
            auth,
            expires_in_seconds: Some(ttl),
        });
    }
    Ok(entries)
}

impl DockerAuthConfig {
    fn to_registry_auth(&self) -> Option<String> {
        if let Some(auth) = self.auth.as_ref().filter(|value| !value.is_empty()) {
            return Some(auth.clone());
        }
        match (self.username.as_deref(), self.password.as_deref()) {
            (Some(username), Some(password)) if !username.is_empty() || !password.is_empty() => {
                Some(STANDARD.encode(format!("{username}:{password}").as_bytes()))
            }
            _ => {
                let _unsupported_identity_token = self.identity_token.as_ref()?;
                None
            }
        }
    }
}

fn normalize_registry_scope(scope: &str) -> String {
    scope
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string()
}

fn parse_cache_duration_value(value: &Value) -> Option<u64> {
    match value {
        Value::String(value) => parse_go_duration_seconds(value),
        Value::Object(map) => map
            .get("duration")
            .and_then(Value::as_str)
            .and_then(parse_go_duration_seconds),
        _ => None,
    }
}

fn parse_go_duration_seconds(value: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut number = String::new();
    let mut saw_unit = false;
    for ch in value.trim().chars() {
        if ch.is_ascii_digit() {
            number.push(ch);
            continue;
        }
        if number.is_empty() {
            return None;
        }
        let amount = number.parse::<u64>().ok()?;
        number.clear();
        let seconds = match ch {
            's' => amount,
            'm' => amount.saturating_mul(60),
            'h' => amount.saturating_mul(60 * 60),
            _ => return None,
        };
        total = total.saturating_add(seconds);
        saw_unit = true;
    }
    if !number.is_empty() || !saw_unit {
        return None;
    }
    Some(total)
}

fn put_auth(socket: &Path, entries: &[RuntimeAuthEntry]) -> Result<AuthResponse> {
    let body = serde_json::to_vec(entries).context("failed to encode runtime auth request")?;
    let mut stream = UnixStream::connect(socket).with_context(|| {
        format!(
            "failed to connect to nydus sysctl socket {}",
            socket.display()
        )
    })?;
    let header = format!(
        "PUT /api/v1/auth HTTP/1.1\r\nHost: nydus-snapshotter\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .context("failed to write auth request headers")?;
    stream
        .write_all(&body)
        .context("failed to write auth request body")?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .context("failed to read auth response")?;
    parse_auth_response(&response)
}

fn parse_auth_response(response: &[u8]) -> Result<AuthResponse> {
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
            "nydus sysctl rejected auth injection with HTTP {status}: {}",
            String::from_utf8_lossy(body)
        );
    }
    serde_json::from_slice(body).context("failed to decode nydus auth response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_kubelet_response_to_runtime_entries() {
        let payload = br#"{
            "apiVersion":"credentialprovider.kubelet.k8s.io/v1",
            "kind":"CredentialProviderResponse",
            "cacheDuration":"5m0s",
            "auth":{
                "registry.local/team":{"username":"user","password":"pass"},
                "*.wildcard.local":{"username":"skip","password":"skip"}
            }
        }"#;

        let entries = extract_runtime_auth(payload, InputFormat::Kubelet, 30).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].registry, "registry.local/team");
        assert_eq!(entries[0].auth, "dXNlcjpwYXNz");
        assert_eq!(entries[0].expires_in_seconds, Some(300));
    }

    #[test]
    fn accepts_native_runtime_array() {
        let payload = br#"[{"registry":"registry.local","auth":"abc","expires_in_seconds":60}]"#;
        let entries = extract_runtime_auth(payload, InputFormat::Auto, 30).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].registry, "registry.local");
    }

    #[test]
    fn parses_go_duration_subset() {
        assert_eq!(parse_go_duration_seconds("5m0s"), Some(300));
        assert_eq!(parse_go_duration_seconds("1h2m3s"), Some(3723));
        assert_eq!(parse_go_duration_seconds("300"), None);
    }

    #[test]
    fn parses_successful_sysctl_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{\"registries\":2}";
        assert_eq!(parse_auth_response(response).unwrap().registries, 2);
    }
}
