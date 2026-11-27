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
/// Idle limit of `retention_idle_limit = "auto"` while an image's start gap is unknown: a daily
/// job keeps its stage with two hours to spare.
pub const AUTO_IDLE_LIMIT: Duration = Duration::from_secs(26 * HOUR);
/// Bounds of a learned idle limit.
pub const AUTO_MIN_LIMIT: Duration = Duration::from_secs(HOUR);
pub const AUTO_MAX_LIMIT: Duration = Duration::from_secs(30 * 24 * HOUR);

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
            .map_err(|_| {
                "expected a byte count with an optional unit (B, K, M, G, T, Ki, Mi, Gi, Ti) or a \
                 percentage"
                    .to_string()
            })
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

    /// The idle limit, in seconds, of a stage whose image has the learned start gap `gap`
    /// ([`learn_gap`]): `"auto"` allows twice the gap, within [`AUTO_MIN_LIMIT`] and
    /// [`AUTO_MAX_LIMIT`], and [`AUTO_IDLE_LIMIT`] while it is unknown.
    pub fn secs(self, gap: Option<u64>) -> u64 {
        match (self, gap) {
            (Self::Fixed(limit), _) => limit.as_secs(),
            (Self::Auto, None) => AUTO_IDLE_LIMIT.as_secs(),
            (Self::Auto, Some(gap)) => gap
                .saturating_mul(2)
                .clamp(AUTO_MIN_LIMIT.as_secs(), AUTO_MAX_LIMIT.as_secs()),
        }
    }
}

/// The start gap `G` of an image, learned at a start at `now` from its previous `G` and its last
/// stop: `G = max(now - stopped_at, 0.75 * G)`. So `G` follows a longer gap at once and forgets
/// one slowly, by a quarter per start. A stop in the future (the clock stepped back) teaches
/// nothing.
pub fn learn_gap(previous: Option<u64>, stopped_at: i64, now: i64) -> Option<u64> {
    if now < stopped_at {
        return previous;
    }
    let gap = now.abs_diff(stopped_at);
    Some(previous.map_or(gap, |g| gap.max(g - g / 4)))
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
    /// Its image's learned start gap, in seconds ([`learn_gap`]).
    pub gap: Option<u64>,
    /// Its eviction failed or was refused this pass: it still counts against the limits, but is
    /// not chosen again.
    pub pinned: bool,
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
/// highest idle time relative to its limit ([`IdleLimit::secs`]), the larger one first on a tie. The deficit is the
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
    let limit = |stage: &Stage| policy.idle_limit.secs(stage.gap).max(1);
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
    // idle(a) / limit(a) > idle(b) / limit(b), without rounding.
    let relative = |a: &Stage, b: &Stage| u128::from(idle(a)) * u128::from(limit(b));
    order.sort_by(|a, b| {
        relative(b, a)
            .cmp(&relative(a, b))
            .then(b.bytes.cmp(&a.bytes))
            .then(a.slug.cmp(&b.slug))
    });
    let mut evict = Vec::new();
    for stage in order {
        if stage.pinned {
            continue;
        }
        let reason = if idle(stage) >= limit(stage) {
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
            gap: None,
            pinned: false,
        }
    }

    fn pinned(mut stage: Stage) -> Stage {
        stage.pinned = true;
        stage
    }

    fn learned(mut stage: Stage, gap_hours: u64) -> Stage {
        stage.gap = Some(gap_hours * 3600);
        stage
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
    }

    #[test]
    fn idle_limits_follow_the_learned_gap() {
        let hour = 3600;
        assert_eq!(IdleLimit::Auto.secs(None), 26 * hour);
        assert_eq!(IdleLimit::Auto.secs(Some(12 * hour)), 24 * hour);
        assert_eq!(IdleLimit::Auto.secs(Some(60)), hour, "at least an hour");
        assert_eq!(
            IdleLimit::Auto.secs(Some(60 * 24 * hour)),
            30 * 24 * hour,
            "at most 30 days"
        );
        assert_eq!(IdleLimit::Auto.secs(Some(u64::MAX)), 30 * 24 * hour);
        let fixed = IdleLimit::Fixed(Duration::from_secs(5 * hour));
        assert_eq!(fixed.secs(Some(100 * hour)), 5 * hour);
    }

    #[test]
    fn the_start_gap_is_learned_from_each_start() {
        assert_eq!(learn_gap(None, 100, 400), Some(300));
        assert_eq!(
            learn_gap(Some(100), 0, 1000),
            Some(1000),
            "a longer gap at once"
        );
        assert_eq!(
            learn_gap(Some(1000), 100, 200),
            Some(750),
            "a quarter per start"
        );
        assert_eq!(learn_gap(Some(1000), 100, 1000), Some(900));
        // The clock stepped back past the stop: nothing to learn.
        assert_eq!(learn_gap(Some(500), 1000, 900), Some(500));
        assert_eq!(learn_gap(None, 1000, 900), None);

        // A twice-daily job, then one start right after a stop: its stage is kept for a day.
        let half_day = 12 * 3600;
        let mut gap = None;
        for _ in 0..10 {
            gap = learn_gap(gap, 0, half_day);
        }
        assert_eq!(gap, Some(half_day as u64));
        gap = learn_gap(gap, 0, 60);
        assert_eq!(IdleLimit::Auto.secs(gap), 18 * 3600);
        // A weekly job outlives the 26 h fallback once its gap is known.
        assert_eq!(
            IdleLimit::Auto.secs(learn_gap(None, 0, 7 * 86400)),
            14 * 86400
        );
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
                "auto: twice the learned gap, 26 h while unknown",
                policy("10%", "20%", "auto"),
                vec![
                    learned(stage("hourly", 1, 3), 1),
                    learned(stage("daily", 1, 30), 24),
                    stage("unknown", 1, 25),
                    stage("unknown-old", 1, 27),
                ],
                roomy,
                0,
                vec![("hourly", Reason::Idle), ("unknown-old", Reason::Idle)],
            ),
            (
                "under pressure: idle relative to the limit, not idle time",
                policy("1GiB", "0%", "auto"),
                vec![
                    learned(stage("weekly", 1, 100), 7 * 24),
                    learned(stage("hourly", 1, 1), 1),
                ],
                roomy,
                0,
                vec![("hourly", Reason::MaxBytes)],
            ),
            (
                "a stage that could not be evicted still counts, and the next ones go instead",
                policy("2GiB", "0%", "26h"),
                vec![
                    pinned(stage("stuck", 2, 30)),
                    stage("b", 1, 3),
                    stage("c", 1, 2),
                    stage("d", 1, 1),
                ],
                roomy,
                0,
                vec![
                    ("b", Reason::MaxBytes),
                    ("c", Reason::MaxBytes),
                    ("d", Reason::MaxBytes),
                ],
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

    mod properties {
        use proptest::prelude::*;

        use super::*;

        const UNITS: [(&str, u64); 9] = [
            ("", 1),
            ("B", 1),
            ("K", 1_000),
            ("M", 1_000_000),
            ("G", 1_000_000_000),
            ("Ki", 1 << 10),
            ("Mi", 1 << 20),
            ("Gi", 1 << 30),
            ("Ti", 1 << 40),
        ];

        fn stages() -> impl Strategy<Value = Vec<Stage>> {
            // Whole hours and GiB alongside arbitrary values, so ties in the ordering occur.
            let stage = (
                prop_oneof![0..64 * GIB, (0..8u64).prop_map(|g| g * GIB)],
                // Up to 40 days idle, or up to a day in the future (the clock stepped back).
                prop_oneof![-86_400i64..40 * 86_400, (-2i64..60).prop_map(|h| h * 3600)],
                proptest::option::of(prop_oneof![
                    0..60 * 86_400u64,
                    (0..48u64).prop_map(|h| h * 3600)
                ]),
                proptest::bool::weighted(0.2),
            );
            proptest::collection::vec(stage, 0..12).prop_map(|stages| {
                stages
                    .into_iter()
                    .enumerate()
                    .map(|(i, (bytes, idle, gap, pinned))| Stage {
                        slug: format!("s{i}"),
                        bytes,
                        stopped_at: NOW - idle,
                        gap,
                        pinned,
                    })
                    .collect()
            })
        }

        fn sizes() -> impl Strategy<Value = Size> {
            prop_oneof![
                (0..256 * GIB).prop_map(Size::Bytes),
                (0.0..=100.0f64).prop_map(Size::Percent),
            ]
        }

        fn policies() -> impl Strategy<Value = Policy> {
            let idle_limit = prop_oneof![
                Just(IdleLimit::Auto),
                prop_oneof![0..30 * 86_400u64, (0..96u64).prop_map(|h| h * 3600)]
                    .prop_map(|s| IdleLimit::Fixed(Duration::from_secs(s))),
            ];
            (sizes(), sizes(), idle_limit).prop_map(|(max_bytes, min_free, idle_limit)| Policy {
                max_bytes,
                min_free,
                idle_limit,
            })
        }

        fn filesystems() -> impl Strategy<Value = Filesystem> {
            (0..1024 * GIB)
                .prop_flat_map(|total| (Just(total), 0..=total))
                .prop_map(|(total, available)| Filesystem { total, available })
        }

        proptest! {
            /// Each eviction names a stage once and never a pinned one; an eviction for a reason
            /// other than idleness happens only while a deficit remains, and then meets it if
            /// the unpinned stages hold enough bytes.
            #[test]
            fn plan_evicts_only_what_a_deficit_or_the_idle_limit_asks_for(
                policy in policies(),
                stages in stages(),
                fs in filesystems(),
                cache_excess in 0..64 * GIB,
            ) {
                let limit = |s: &Stage| policy.idle_limit.secs(s.gap).max(1);
                let idle = |s: &Stage| NOW.saturating_sub(s.stopped_at).max(0) as u64;
                let by_slug = |slug: &str| stages.iter().find(|s| s.slug == slug).unwrap();
                let retained: u64 = stages.iter().map(|s| s.bytes).sum();
                let deficit = retained
                    .saturating_sub(policy.max_bytes.bytes(fs.total))
                    .max(policy.min_free.bytes(fs.total).saturating_sub(fs.available))
                    .max(cache_excess);

                let evict = plan(&policy, &stages, fs, cache_excess, NOW);
                let mut freed = 0u64;
                let mut seen = std::collections::HashSet::new();
                for (slug, reason) in &evict {
                    let stage = by_slug(slug);
                    prop_assert!(seen.insert(slug.clone()), "{slug} evicted twice");
                    prop_assert!(!stage.pinned, "pinned {slug} evicted");
                    if *reason == Reason::Idle {
                        prop_assert!(idle(stage) >= limit(stage));
                    } else {
                        prop_assert!(freed < deficit, "{slug} evicted with the deficit met");
                    }
                    freed = freed.saturating_add(stage.bytes);
                }
                let evictable: u64 = stages.iter().filter(|s| !s.pinned).map(|s| s.bytes).sum();
                if evictable >= deficit {
                    prop_assert!(freed >= deficit, "freed {freed} of a {deficit} deficit");
                }
                for stage in stages.iter().filter(|s| !s.pinned && !seen.contains(&s.slug)) {
                    prop_assert!(idle(stage) < limit(stage), "{} kept past its limit", stage.slug);
                }
            }

            /// Stages past their limit go first; then the highest idle time relative to the
            /// limit, the larger stage first on a tie.
            #[test]
            fn plan_orders_evictions(
                policy in policies(),
                stages in stages(),
                fs in filesystems(),
                cache_excess in 0..64 * GIB,
            ) {
                let limit = |s: &Stage| u128::from(policy.idle_limit.secs(s.gap).max(1));
                let idle = |s: &Stage| u128::from(NOW.saturating_sub(s.stopped_at).max(0) as u64);
                let by_slug = |slug: &str| stages.iter().find(|s| s.slug == slug).unwrap();
                let evict = plan(&policy, &stages, fs, cache_excess, NOW);
                for pair in evict.windows(2) {
                    let (a, b) = (by_slug(&pair[0].0), by_slug(&pair[1].0));
                    prop_assert!(pair[0].1 == Reason::Idle || pair[1].1 != Reason::Idle);
                    let (ra, rb) = (idle(a) * limit(b), idle(b) * limit(a));
                    prop_assert!(ra >= rb, "{} before the more idle {}", a.slug, b.slug);
                    prop_assert!(ra > rb || a.bytes >= b.bytes, "{} before the larger {}", a.slug, b.slug);
                }
            }

            /// A learned limit stays within its clamp whatever the starts and stops, the clock
            /// stepping back included, and a stop in the future teaches nothing.
            #[test]
            fn learned_idle_limits_stay_clamped(
                events in proptest::collection::vec((any::<i64>(), any::<i64>()), 1..20),
            ) {
                let mut gap = None;
                for (stopped_at, now) in events {
                    let previous = gap;
                    gap = learn_gap(gap, stopped_at, now);
                    if now < stopped_at {
                        prop_assert_eq!(gap, previous);
                    } else if let Some(p) = previous {
                        prop_assert!(gap.unwrap() >= p - p / 4);
                    }
                    let secs = IdleLimit::Auto.secs(gap);
                    if gap.is_none() {
                        prop_assert_eq!(secs, AUTO_IDLE_LIMIT.as_secs());
                    }
                    prop_assert!((AUTO_MIN_LIMIT.as_secs()..=AUTO_MAX_LIMIT.as_secs()).contains(&secs));
                }
            }

            /// Byte counts round-trip with every unit, in any case and with surrounding spaces.
            #[test]
            fn byte_sizes_round_trip(
                n in prop_oneof![0..1u64 << 24, any::<u64>()],
                unit in 0..UNITS.len(), upper in any::<bool>()) {
                let (suffix, multiplier) = UNITS[unit];
                let suffix = if upper { suffix.to_uppercase() } else { suffix.to_lowercase() };
                let parsed = Size::parse(&format!(" {n}{suffix} "));
                match n.checked_mul(multiplier) {
                    Some(bytes) => prop_assert_eq!(parsed, Ok(Size::Bytes(bytes))),
                    None => prop_assert!(parsed.is_err()),
                }
            }

            /// A percentage parses back exactly within 0%..=100%, is refused outside it, and
            /// never claims more than the filesystem.
            #[test]
            fn percent_sizes_round_trip(p in -1e3..1e3f64, total in any::<u64>()) {
                let parsed = Size::parse(&format!("{p}%"));
                if (0.0..=100.0).contains(&p) {
                    prop_assert_eq!(parsed, Ok(Size::Percent(p)));
                    prop_assert!(Size::Percent(p).bytes(total) <= total);
                } else {
                    prop_assert!(parsed.is_err());
                }
            }

            /// Arbitrary input is refused or parsed, never a panic, and a parsed percentage is
            /// within bounds.
            #[test]
            fn sizes_reject_garbage(value in "\\PC*|[0-9 .eE+-]*[%a-zA-Z]{0,4}") {
                if let Ok(Size::Percent(p)) = Size::parse(&value) {
                    prop_assert!((0.0..=100.0).contains(&p), "{value:?} gave {p}%");
                }
            }
        }
    }
}
