// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! OCI image encryption support.
//!
//! Decrypts encrypted Nydus layers using OCICrypt or age envelope encryption.

use anyhow::{Context, Result};
use base64::prelude::*;
use serde::Serialize;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;

use compio::io::{AsyncWrite, AsyncWriteExt};
use compio::process::Command;
use compio::time::timeout;

const DECRYPT_HELPER_ENV: &str = "NYDUS_SNAPSHOTTER_DECRYPT_HELPER";

/// Encryption formats the snapshotter can identify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionFormat {
    Ocicrypt,
    Age,
    Unknown,
}

/// Typed encryption errors. Full cryptographic backends are intentionally not
/// hidden behind a generic `anyhow` string so callers can report actionable
/// setup problems.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("encrypted layer key is empty")]
    EmptyKey,
    #[error(
        "{format:?} encrypted layers require an OCICrypt/age backend that is not linked into this build"
    )]
    BackendUnavailable { format: EncryptionFormat },
    #[error("configured encryption helper path is empty")]
    EmptyHelperPath,
    #[error("encryption helper timed out")]
    HelperTimedOut,
    #[error("encryption helper exited unsuccessfully: {status}")]
    HelperFailed { status: String },
}

/// Request passed to an encryption provider. Key material is intentionally
/// carried in-memory and never embedded into command-line arguments.
#[derive(Clone, Copy)]
pub struct DecryptionRequest<'a> {
    pub encrypted_data: &'a [u8],
    pub key: &'a [u8],
    pub format: EncryptionFormat,
}

/// Pluggable decryption backend.
pub trait EncryptionProvider: Send + Sync {
    fn decrypt<'a>(
        &'a self,
        request: DecryptionRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + 'a>>;
}

/// External helper provider for OCICrypt/imgcrypt/age implementations.
///
/// Helper protocol:
/// - stdin: JSON `{ "format", "key", "ciphertext" }` where binary fields are base64.
/// - stdout: raw plaintext bytes.
/// - stderr: diagnostic text, not exposed verbatim to avoid secret leakage.
pub struct CommandEncryptionProvider {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

impl CommandEncryptionProvider {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl EncryptionProvider for CommandEncryptionProvider {
    fn decrypt<'a>(
        &'a self,
        request: DecryptionRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + 'a>> {
        Box::pin(async move {
            if self.program.as_os_str().is_empty() {
                return Err(EncryptionError::EmptyHelperPath.into());
            }
            let payload = serde_json::to_vec(&HelperRequest {
                format: format_label(request.format),
                key: BASE64_STANDARD.encode(request.key),
                ciphertext: BASE64_STANDARD.encode(request.encrypted_data),
            })
            .context("failed to encode encryption helper request")?;

            let mut command = Command::new(&self.program);
            command.args(&self.args);
            // compio's stdio builders are fallible and don't chain; configure
            // them individually. compio has no `kill_on_drop`, but the helper is
            // short-lived and bounded by `timeout` below.
            command.stdin(Stdio::piped())?;
            command.stdout(Stdio::piped())?;
            command.stderr(Stdio::piped())?;
            let mut child = command.spawn().with_context(|| {
                format!(
                    "failed to spawn encryption helper {}",
                    self.program.display()
                )
            })?;
            let mut stdin = child
                .stdin
                .take()
                .context("encryption helper stdin was unavailable")?;
            let write_task = compio::runtime::spawn(async move {
                // compio I/O takes an owned buffer and returns `BufResult`.
                stdin.write_all(payload).await.0?;
                stdin.shutdown().await
            });
            let output = timeout(self.timeout, child.wait_with_output())
                .await
                .map_err(|_| EncryptionError::HelperTimedOut)??;
            write_task
                .await
                .map_err(|e| anyhow::anyhow!("encryption helper stdin task failed: {e}"))?
                .context("failed to write encryption helper request")?;
            if !output.status.success() {
                return Err(EncryptionError::HelperFailed {
                    status: output.status.to_string(),
                }
                .into());
            }
            Ok(output.stdout)
        })
    }
}

/// Identify the likely encryption wrapper. OCI encrypted layers commonly carry
/// JWE-like JSON envelopes; age payloads start with `age-encryption.org/`.
pub fn detect_format(encrypted_data: &[u8]) -> EncryptionFormat {
    let trimmed = encrypted_data
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .collect::<Vec<_>>();
    if trimmed.starts_with(b"age-encryption.org/") {
        EncryptionFormat::Age
    } else if trimmed.starts_with(b"{")
        && (trimmed.windows(5).any(|w| w == b"\"jwe\"")
            || trimmed.windows(10).any(|w| w == b"\"ciphertext"))
    {
        EncryptionFormat::Ocicrypt
    } else {
        EncryptionFormat::Unknown
    }
}

/// Decrypt an encrypted layer blob using the configured production provider.
pub async fn decrypt_layer(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(EncryptionError::EmptyKey.into());
    }
    if let Ok(helper) = std::env::var(DECRYPT_HELPER_ENV) {
        let provider = CommandEncryptionProvider::new(helper);
        return decrypt_layer_with_provider(encrypted_data, key, &provider).await;
    }
    Err(EncryptionError::BackendUnavailable {
        format: detect_format(encrypted_data),
    }
    .into())
}

/// Decrypt an encrypted layer blob using an explicit provider.
pub async fn decrypt_layer_with_provider(
    encrypted_data: &[u8],
    key: &[u8],
    provider: &dyn EncryptionProvider,
) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(EncryptionError::EmptyKey.into());
    }
    provider
        .decrypt(DecryptionRequest {
            encrypted_data,
            key,
            format: detect_format(encrypted_data),
        })
        .await
}

#[derive(Serialize)]
struct HelperRequest {
    format: &'static str,
    key: String,
    ciphertext: String,
}

fn format_label(format: EncryptionFormat) -> &'static str {
    match format {
        EncryptionFormat::Ocicrypt => "ocicrypt",
        EncryptionFormat::Age => "age",
        EncryptionFormat::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_age_and_ocicrypt_like_payloads() {
        assert_eq!(
            detect_format(b"age-encryption.org/v1\n..."),
            EncryptionFormat::Age
        );
        assert_eq!(
            detect_format(br#"{"jwe":{"ciphertext":"abc"}}"#),
            EncryptionFormat::Ocicrypt
        );
        assert_eq!(detect_format(b"plain"), EncryptionFormat::Unknown);
    }

    #[compio::test]
    async fn decrypt_layer_reports_missing_key_before_backend() {
        let err = decrypt_layer(b"plain", b"").await.unwrap_err();
        assert!(err.to_string().contains("key is empty"));
    }

    struct EchoProvider;

    impl EncryptionProvider for EchoProvider {
        fn decrypt<'a>(
            &'a self,
            request: DecryptionRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + 'a>> {
            Box::pin(async move {
                assert_eq!(request.format, EncryptionFormat::Unknown);
                assert_eq!(request.key, b"key");
                Ok(request.encrypted_data.to_vec())
            })
        }
    }

    #[compio::test]
    async fn decrypt_layer_uses_explicit_provider() {
        let decrypted = decrypt_layer_with_provider(b"ciphertext", b"key", &EchoProvider)
            .await
            .unwrap();
        assert_eq!(decrypted, b"ciphertext");
    }

    #[test]
    fn helper_format_labels_are_stable() {
        assert_eq!(format_label(EncryptionFormat::Age), "age");
        assert_eq!(format_label(EncryptionFormat::Ocicrypt), "ocicrypt");
        assert_eq!(format_label(EncryptionFormat::Unknown), "unknown");
    }
}
