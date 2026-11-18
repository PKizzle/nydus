// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Retention of released fanotify stages.
//!
//! When the last container of an image exits, its daemon stops and its mount goes, but with
//! `[snapshotter.cache] retention = true` its `daemons/<slug>/stage` (node view and verified
//! caches) stays, so the next start of the image is warm. A stage is *retained* while its image
//! has a stopped daemon record and no daemon; nothing else (no daemon, mount or fd) is kept.
//!
//! [`plan`] is the whole policy, a pure function: the reconciler gathers its inputs once per
//! tick and `DaemonSupervisor::evict_retained` carries out each eviction under the image's start
//! lock.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::config::{CacheConfig, ConfigError};

const HOUR: u64 = 3600;
/// Idle limit of `retention_idle_limit = "auto"`: a daily job keeps its stage with two hours to
/// spare.
pub const AUTO_IDLE_LIMIT: Duration = Duration::from_secs(26 * HOUR);

/// A size limit: bytes, or a percentage of the filesystem holding `daemons/`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Size {
    Bytes(u64),
    Percent(f64),
}

impl Size {
    /// Parse `"10%"`, `"20GiB"`, `"500M"` or a plain byte count.
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if let Some(percent) = value.strip_suffix('%') {
            return match percent.trim().parse::<f64>() {
                Ok(p) if (0.0..=100.0).contains(&p) => Ok(Self::Percent(p)),
                _ => Err("expected a percentage between 0% and 100%".to_string()),
            };
        }
        if value == "max" {
            return Err("expected a byte count or a percentage".to_string());
        }
        crate::cgroup::normalize_memory_value(value)
            .map(|bytes| Self::Bytes(bytes.parse().expect("normalized byte value")))
            .map_err(|e| format!("{e:#}"))
    }

    /// The limit in bytes on a filesystem of `total` bytes.
    pub fn bytes(self, total: u64) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::Percent(p) => (total as f64 * p / 100.0) as u64,
        }
    }
}

/// How long a retained stage may stay idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleLimit {
    Auto,
    Fixed(Duration),
}

impl IdleLimit {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim() {
            "auto" => Ok(Self::Auto),
            other => crate::cache::parse_duration(other)
                .map(Self::Fixed)
                .map_err(|e| format!("expected \"auto\" or a duration: {e}")),
        }
    }

    /// The idle limit of one stage, in seconds.
    pub fn secs(self) -> u64 {
        match self {
            Self::Auto => AUTO_IDLE_LIMIT.as_secs(),
            Self::Fixed(limit) => limit.as_secs(),
        }
    }
}

/// The retention settings of `[snapshotter.cache]`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Policy {
    pub max_bytes: Size,
    pub min_free: Size,
    pub idle_limit: IdleLimit,
}

impl Policy {
    /// The policy `cache` configures, `None` with retention off. Every key is checked either way.
    pub fn from_config(cache: &CacheConfig) -> Result<Option<Self>, ConfigError> {
        fn check<T>(
            field: &'static str,
            value: &str,
            parse: fn(&str) -> Result<T, String>,
        ) -> Result<T, ConfigError> {
            parse(value).map_err(|reason| ConfigError::InvalidRetentionSetting {
                field,
                value: value.to_string(),
                reason,
            })
        }
        let policy = Self {
            max_bytes: check(
                "retention_max_bytes",
                &cache.retention_max_bytes,
                Size::parse,
            )?,
            min_free: check("retention_min_free", &cache.retention_min_free, Size::parse)?,
            idle_limit: check(
                "retention_idle_limit",
                &cache.retention_idle_limit,
                IdleLimit::parse,
            )?,
        };
        Ok(cache.retention.then_some(policy))
    }
}

/// A retained stage, as [`plan`] sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage {
    pub slug: String,
    /// Bytes allocated on disk.
    pub bytes: u64,
    /// When its daemon stopped (Unix seconds).
    pub stopped_at: i64,
}

/// Size and free space of the filesystem holding `daemons/`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Filesystem {
    pub total: u64,
    pub available: u64,
}

/// Why a retained stage is evicted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reason {
    /// Idle longer than its limit.
    Idle,
    /// Retained stages exceed `retention_max_bytes`.
    MaxBytes,
    /// The filesystem has less than `retention_min_free` available.
    MinFree,
    /// All caches exceed `gc_max_bytes`: retained stages go before any `work_dir` file.
    GcMaxBytes,
}

impl Reason {
    pub const ALL: [Reason; 4] = [
        Reason::Idle,
        Reason::MaxBytes,
        Reason::MinFree,
        Reason::GcMaxBytes,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::MaxBytes => "max_bytes",
            Self::MinFree => "min_free",
            Self::GcMaxBytes => "gc_max_bytes",
        }
    }
}

/// The retained stages to evict, in order, each with its reason.
///
/// Stages idle past their limit go first, then, while a deficit remains, the stage with the
/// highest idle time relative to its limit, the larger one first on a tie. The deficit is the
/// largest of: retained bytes over `max_bytes`, `min_free` over available space, and
/// `cache_excess` (all cache bytes over `gc_max_bytes`, 0 without it); every eviction lowers each
/// term by the stage's bytes. A stop time in the future (the clock stepped back) counts as idle
/// for zero seconds.
pub fn plan(
    policy: &Policy,
    stages: &[Stage],
    fs: Filesystem,
    cache_excess: u64,
    now: i64,
) -> Vec<(String, Reason)> {
    let limit = policy.idle_limit.secs().max(1);
    let idle = |stage: &Stage| now.saturating_sub(stage.stopped_at).max(0) as u64;
    let retained: u64 = stages.iter().map(|s| s.bytes).sum();
    let mut deficits = [
        (
            Reason::MaxBytes,
            retained.saturating_sub(policy.max_bytes.bytes(fs.total)),
        ),
        (
            Reason::MinFree,
            policy.min_free.bytes(fs.total).saturating_sub(fs.available),
        ),
        (Reason::GcMaxBytes, cache_excess),
    ];
    let mut order: Vec<&Stage> = stages.iter().collect();
    order.sort_by(|a, b| {
        idle(b)
            .cmp(&idle(a))
            .then(b.bytes.cmp(&a.bytes))
            .then(a.slug.cmp(&b.slug))
    });
    let mut evict = Vec::new();
    for stage in order {
        let reason = if idle(stage) >= limit {
            Reason::Idle
        } else {
            match deficits.iter().max_by_key(|(_, deficit)| *deficit) {
                Some(&(reason, deficit)) if deficit > 0 => reason,
                _ => break,
            }
        };
        for (_, deficit) in &mut deficits {
            *deficit = deficit.saturating_sub(stage.bytes);
        }
        evict.push((stage.slug.clone(), reason));
    }
    evict
}

/// What the last retention pass found, for the metrics endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gauges {
    pub retained_stages: u64,
    pub retained_bytes: u64,
    pub max_bytes: u64,
    pub min_free: u64,
    pub fs_available: u64,
}

/// Retention counters and the gauges of the last pass.
#[derive(Debug, Default)]
pub struct Stats {
    evictions: [AtomicU64; Reason::ALL.len()],
    starts_warm: AtomicU64,
    starts_cold: AtomicU64,
    gauges: Mutex<Option<Gauges>>,
}

impl Stats {
    pub fn record_eviction(&self, reason: Reason) {
        self.evictions[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn evictions(&self, reason: Reason) -> u64 {
        self.evictions[reason as usize].load(Ordering::Relaxed)
    }

    /// Count a fanotify start: warm when it found a staged mount source to start from.
    pub fn record_start(&self, warm: bool) {
        let counter = if warm {
            &self.starts_warm
        } else {
            &self.starts_cold
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Fanotify starts (warm, cold).
    pub fn starts(&self) -> (u64, u64) {
        (
            self.starts_warm.load(Ordering::Relaxed),
            self.starts_cold.load(Ordering::Relaxed),
        )
    }

    pub fn set_gauges(&self, gauges: Gauges) {
        *self.gauges.lock().unwrap() = Some(gauges);
    }

    pub fn gauges(&self) -> Option<Gauges> {
        *self.gauges.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const NOW: i64 = 1_000_000_000;

    fn stage(slug: &str, gib: u64, idle_hours: i64) -> Stage {
        Stage {
            slug: slug.to_string(),
            bytes: gib * GIB,
            stopped_at: NOW - idle_hours * 3600,
        }
    }

    fn policy(max_bytes: &str, min_free: &str, idle_limit: &str) -> Policy {
        Policy {
            max_bytes: Size::parse(max_bytes).unwrap(),
            min_free: Size::parse(min_free).unwrap(),
            idle_limit: IdleLimit::parse(idle_limit).unwrap(),
        }
    }

    #[test]
    fn sizes_and_limits_parse() {
        assert_eq!(Size::parse("10%"), Ok(Size::Percent(10.0)));
        assert_eq!(Size::parse(" 12.5 % "), Ok(Size::Percent(12.5)));
        assert_eq!(Size::parse("20GiB"), Ok(Size::Bytes(20 * GIB)));
        assert_eq!(Size::parse("500M"), Ok(Size::Bytes(500_000_000)));
        assert_eq!(Size::parse("4096"), Ok(Size::Bytes(4096)));
        for bad in ["", "101%", "-1%", "x%", "max", "10 parsecs", "GiB"] {
            assert!(Size::parse(bad).is_err(), "{bad:?} parsed");
        }
        assert_eq!(Size::Percent(10.0).bytes(1000), 100);
        assert_eq!(Size::Bytes(7).bytes(1000), 7);

        assert_eq!(IdleLimit::parse("auto"), Ok(IdleLimit::Auto));
        assert_eq!(
            IdleLimit::parse("7d"),
            Ok(IdleLimit::Fixed(Duration::from_secs(7 * 86400)))
        );
        assert!(IdleLimit::parse("soon").is_err());
        assert_eq!(IdleLimit::Auto.secs(), 26 * 3600);
    }

    /// One row per scenario: stages as (slug, GiB, hours idle), the filesystem in GiB
    /// (total, available), the `gc_max_bytes` excess in GiB, and the expected evictions.
    #[test]
    fn plan_table() {
        type Row = (
            &'static str,
            Policy,
            Vec<Stage>,
            (u64, u64),
            u64,
            Vec<(&'static str, Reason)>,
        );
        let roomy = (1000, 900);
        let rows: Vec<Row> = vec![
            (
                "nothing to do",
                policy("10%", "20%", "26h"),
                vec![stage("a", 1, 1), stage("b", 2, 25)],
                roomy,
                0,
                vec![],
            ),
            (
                "idle past the limit, whatever the room",
                policy("10%", "20%", "26h"),
                vec![stage("a", 1, 1), stage("b", 2, 26), stage("c", 1, 30)],
                roomy,
                0,
                vec![("c", Reason::Idle), ("b", Reason::Idle)],
            ),
            (
                "over the byte budget: most idle first until under it",
                policy("4GiB", "0%", "7d"),
                vec![stage("a", 3, 1), stage("b", 2, 5), stage("c", 2, 3)],
                roomy,
                0,
                vec![("b", Reason::MaxBytes), ("c", Reason::MaxBytes)],
            ),
            (
                "percent budget of the filesystem",
                policy("1%", "0%", "7d"),
                vec![stage("a", 6, 1), stage("b", 6, 2)],
                roomy,
                0,
                vec![("b", Reason::MaxBytes)],
            ),
            (
                "equal idle time: the larger stage first",
                policy("4GiB", "0%", "7d"),
                vec![stage("small", 1, 2), stage("large", 3, 2), stage("x", 1, 1)],
                roomy,
                0,
                vec![("large", Reason::MaxBytes)],
            ),
            (
                "below the free-space floor",
                policy("100%", "20%", "7d"),
                vec![stage("a", 5, 1), stage("b", 5, 2), stage("c", 5, 3)],
                (100, 12),
                0,
                vec![("c", Reason::MinFree), ("b", Reason::MinFree)],
            ),
            (
                "the floor cannot be met: everything retained goes",
                policy("100%", "50%", "7d"),
                vec![stage("a", 1, 1), stage("b", 1, 2)],
                (100, 10),
                0,
                vec![("b", Reason::MinFree), ("a", Reason::MinFree)],
            ),
            (
                "gc_max_bytes: retained stages go before any work_dir file",
                policy("100%", "0%", "7d"),
                vec![stage("a", 2, 1), stage("b", 2, 2)],
                roomy,
                3,
                vec![("b", Reason::GcMaxBytes), ("a", Reason::GcMaxBytes)],
            ),
            (
                "the largest deficit names the reason; idle evictions count against it",
                policy("6GiB", "20%", "26h"),
                vec![stage("a", 2, 1), stage("b", 4, 2), stage("old", 3, 40)],
                (100, 15),
                1,
                vec![("old", Reason::Idle), ("b", Reason::MinFree)],
            ),
            (
                "clock stepped back: a stop in the future is not idle",
                policy("10%", "20%", "1h"),
                vec![stage("future", 1, -5), stage("past", 1, 2)],
                roomy,
                0,
                vec![("past", Reason::Idle)],
            ),
        ];
        for (name, policy, stages, (total, available), excess, want) in rows {
            let fs = Filesystem {
                total: total * GIB,
                available: available * GIB,
            };
            let got = plan(&policy, &stages, fs, excess * GIB, NOW);
            let want: Vec<(String, Reason)> =
                want.into_iter().map(|(s, r)| (s.to_string(), r)).collect();
            assert_eq!(got, want, "{name}");
        }
    }
}
