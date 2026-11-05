// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Small retry wrapper for registry pushes.
//!
//! Blob and manifest uploads are digest-addressed and therefore idempotent (a
//! `PUT ...?digest=sha256:...` either lands the exact bytes or is a no-op), so
//! a transient `5xx`/network error can be retried by simply re-running the push
//! from scratch — restart-not-resume is safe. Honors the CLI's
//! `--push-retry-count` / `--push-retry-delay` flags so one flaky response
//! does not abort a long conversion.

use std::fmt::Display;
use std::future::Future;
use std::time::Duration;

use registry_client::RegistryError;
use tracing::warn;

/// Default delay applied when `--push-retry-delay` cannot be parsed.
const DEFAULT_DELAY: Duration = Duration::from_secs(5);

/// A bounded retry policy for idempotent push operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total number of attempts (initial try + retries); always at least 1.
    attempts: u32,
    /// Delay between attempts.
    delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        // Mirrors the convert defaults (--push-retry-count 3, --push-retry-delay 5s).
        Self {
            attempts: 4,
            delay: DEFAULT_DELAY,
        }
    }
}

impl RetryPolicy {
    /// Build a policy from the CLI flags: `retry_count` is the number of
    /// *retries* after the initial attempt, `delay` is a duration string such
    /// as `"5s"`, `"500ms"`, or `"2m"` (bare integers are seconds). An
    /// unparsable delay falls back to [`DEFAULT_DELAY`].
    pub fn from_flags(retry_count: u32, delay: &str) -> Self {
        Self {
            attempts: retry_count.saturating_add(1),
            delay: parse_delay(delay).unwrap_or(DEFAULT_DELAY),
        }
    }

    /// Run `op` up to [`attempts`](Self::attempts) times, sleeping
    /// [`delay`](Self::delay) between failures. `what` labels the operation in
    /// the retry warning. The last error is returned when all attempts fail.
    /// An error that no retry can fix (see [`is_permanent`]) is returned at once.
    ///
    /// Generic over the error type (anything `Display`), so it wraps both
    /// `anyhow::Result` closures and `registry-client` calls returning the
    /// typed `RegistryError` without erasing the error the caller gets back.
    pub async fn run<T, E, F, Fut>(&self, what: &str, mut op: F) -> Result<T, E>
    where
        E: Display + 'static,
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let mut attempt = 1u32;
        loop {
            match op().await {
                Ok(value) => return Ok(value),
                Err(err) if attempt < self.attempts && !is_permanent(&err) => {
                    warn!(
                        operation = what,
                        attempt,
                        attempts = self.attempts,
                        delay = ?self.delay,
                        error = %err,
                        "push attempt failed; retrying"
                    );
                    compio::time::sleep(self.delay).await;
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }
}

/// Whether `err` is a registry answer that the same request will get again:
/// failed auth, a missing resource, a digest mismatch, or any 4xx except
/// 408 (timeout) and 429 (rate limited). Works for a bare [`RegistryError`] and
/// for one anywhere in an `anyhow` chain.
fn is_permanent(err: &dyn std::any::Any) -> bool {
    let registry = err.downcast_ref::<RegistryError>().or_else(|| {
        err.downcast_ref::<anyhow::Error>()
            .and_then(|e| e.chain().find_map(|c| c.downcast_ref::<RegistryError>()))
    });
    match registry {
        Some(RegistryError::Auth(_) | RegistryError::NotFound { .. }) => true,
        Some(RegistryError::DigestMismatch { .. }) => true,
        Some(RegistryError::Http { status, .. }) => {
            (400..500).contains(status) && *status != 408 && *status != 429
        }
        _ => false,
    }
}

/// Parse a duration string (`"5s"`, `"500ms"`, `"2m"`, `"1h"`, or a bare
/// integer treated as seconds). Returns `None` on an unrecognized form.
fn parse_delay(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let split = s.find(|c: char| c.is_ascii_alphabetic());
    let (value, unit) = match split {
        Some(i) => (s[..i].trim(), s[i..].trim()),
        None => (s, "s"),
    };
    let value: f64 = value.parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let seconds = match unit {
        "ms" => value / 1000.0,
        "s" => value,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        _ => return None,
    };
    Some(Duration::from_secs_f64(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::cell::Cell;

    #[test]
    fn parse_delay_handles_units_and_bare_seconds() {
        assert_eq!(parse_delay("5s"), Some(Duration::from_secs(5)));
        assert_eq!(parse_delay("5"), Some(Duration::from_secs(5)));
        assert_eq!(parse_delay("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_delay("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_delay("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_delay(" 3s "), Some(Duration::from_secs(3)));
        assert!(parse_delay("").is_none());
        assert!(parse_delay("garbage").is_none());
        assert!(parse_delay("5x").is_none());
    }

    #[test]
    fn from_flags_sets_attempts_to_retries_plus_one() {
        let policy = RetryPolicy::from_flags(3, "5s");
        assert_eq!(policy.attempts, 4);
        assert_eq!(policy.delay, Duration::from_secs(5));
        // A zero retry count still yields one attempt.
        assert_eq!(RetryPolicy::from_flags(0, "1s").attempts, 1);
        // Bad delay falls back to the default.
        assert_eq!(RetryPolicy::from_flags(1, "nope").delay, DEFAULT_DELAY);
    }

    #[compio::test]
    async fn run_retries_until_success() {
        let policy = RetryPolicy {
            attempts: 3,
            delay: Duration::from_millis(0),
        };
        let calls = Cell::new(0u32);
        let result: Result<u32> = policy
            .run("test", || async {
                let n = calls.get() + 1;
                calls.set(n);
                if n < 3 {
                    Err(anyhow::anyhow!("transient {n}"))
                } else {
                    Ok(n)
                }
            })
            .await;
        assert_eq!(result.unwrap(), 3);
        assert_eq!(calls.get(), 3);
    }

    #[compio::test]
    async fn run_does_not_retry_what_a_retry_cannot_fix() {
        let policy = RetryPolicy {
            attempts: 3,
            delay: Duration::from_millis(0),
        };
        let http = |status| RegistryError::Http {
            status,
            body: String::new(),
            resource: "blob".into(),
        };
        for (err, calls_expected) in [
            (RegistryError::Auth("denied".into()), 1),
            (http(400), 1),
            (http(403), 1),
            (http(408), 3),
            (http(429), 3),
            (http(503), 3),
        ] {
            let calls = Cell::new(0u32);
            let err = std::cell::RefCell::new(Some(err));
            let result: Result<(), RegistryError> = policy
                .run("test", || {
                    calls.set(calls.get() + 1);
                    let e = err.borrow_mut().take();
                    async move {
                        Err(e.unwrap_or_else(|| {
                            RegistryError::Timeout("retried".into())
                        }))
                    }
                })
                .await;
            assert!(result.is_err());
            assert_eq!(calls.get(), calls_expected);
        }

        // Wrapped in anyhow context, a registry error is still recognised.
        let calls = Cell::new(0u32);
        let result: Result<()> = policy
            .run("test", || async {
                calls.set(calls.get() + 1);
                Err(anyhow::Error::new(RegistryError::NotFound {
                    resource: "blob".into(),
                })
                .context("push blob"))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    #[compio::test]
    async fn run_gives_up_after_attempts_exhausted() {
        let policy = RetryPolicy {
            attempts: 2,
            delay: Duration::from_millis(0),
        };
        let calls = Cell::new(0u32);
        let result: Result<()> = policy
            .run("test", || async {
                calls.set(calls.get() + 1);
                Err(anyhow::anyhow!("always fails"))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 2);
    }
}
