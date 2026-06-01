// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Prometheus metrics for the Rust snapshotter.
//!
//! Metric names intentionally include the Go snapshotter names where the Rust
//! in-process design can expose equivalent values. Labels are bounded to avoid
//! unbounded image/path cardinality in operation metrics.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SNAPSHOT_DURATION_BUCKETS_MS: [f64; 14] = [
    0.5, 1.0, 5.0, 10.0, 50.0, 100.0, 150.0, 200.0, 250.0, 300.0, 350.0, 400.0, 600.0, 1000.0,
];

#[derive(Debug)]
pub struct SnapshotterMetrics {
    started_at: Instant,
    snapshot_operations: Mutex<BTreeMap<&'static str, SnapshotOperationStats>>,
}

#[derive(Clone, Debug)]
struct SnapshotOperationStats {
    in_flight: u64,
    total_by_status: BTreeMap<&'static str, u64>,
    duration_count: u64,
    duration_sum_ms: f64,
    duration_buckets: [u64; SNAPSHOT_DURATION_BUCKETS_MS.len()],
}

pub struct SnapshotOperationTimer {
    metrics: Arc<SnapshotterMetrics>,
    operation: &'static str,
    started_at: Instant,
    finished: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CacheMetricSnapshot {
    pub total_bytes: u64,
    pub deleted_blobs: u64,
    pub deletion_errors: u64,
    pub blobs_in_use: u64,
}

impl Default for SnapshotterMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotterMetrics {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            snapshot_operations: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn start_snapshot_operation(
        self: &Arc<Self>,
        operation: &'static str,
    ) -> SnapshotOperationTimer {
        if let Ok(mut operations) = self.snapshot_operations.lock() {
            operations
                .entry(operation)
                .or_insert_with(SnapshotOperationStats::default)
                .in_flight += 1;
        }
        SnapshotOperationTimer {
            metrics: self.clone(),
            operation,
            started_at: Instant::now(),
            finished: false,
        }
    }

    pub fn record_snapshot_operation(
        &self,
        operation: &'static str,
        status: &'static str,
        elapsed: Duration,
    ) {
        let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
        if let Ok(mut operations) = self.snapshot_operations.lock() {
            let stats = operations
                .entry(operation)
                .or_insert_with(SnapshotOperationStats::default);
            *stats.total_by_status.entry(status).or_insert(0) += 1;
            stats.duration_count += 1;
            stats.duration_sum_ms += elapsed_ms;
            for (idx, bucket) in SNAPSHOT_DURATION_BUCKETS_MS.iter().enumerate() {
                if elapsed_ms <= *bucket {
                    stats.duration_buckets[idx] += 1;
                }
            }
        }
    }

    fn finish_snapshot_operation(
        &self,
        operation: &'static str,
        status: &'static str,
        elapsed: Duration,
    ) {
        if let Ok(mut operations) = self.snapshot_operations.lock() {
            let stats = operations
                .entry(operation)
                .or_insert_with(SnapshotOperationStats::default);
            stats.in_flight = stats.in_flight.saturating_sub(1);
        }
        self.record_snapshot_operation(operation, status, elapsed);
    }

    fn cancel_snapshot_operation(&self, operation: &'static str) {
        if let Ok(mut operations) = self.snapshot_operations.lock()
            && let Some(stats) = operations.get_mut(operation)
        {
            stats.in_flight = stats.in_flight.saturating_sub(1);
        }
    }

    pub fn render_prometheus(&self, cache: CacheMetricSnapshot) -> String {
        let mut out = String::new();
        self.render_snapshot_operations(&mut out);
        self.render_process_metrics(&mut out);
        self.render_cache_metrics(&mut out, cache);
        out
    }

    fn render_snapshot_operations(&self, out: &mut String) {
        let operations = match self.snapshot_operations.lock() {
            Ok(operations) => operations.clone(),
            Err(_) => BTreeMap::new(),
        };

        out.push_str("# HELP snapshotter_snapshot_operation_total Snapshotter gRPC operations by method and status.\n");
        out.push_str("# TYPE snapshotter_snapshot_operation_total counter\n");
        for (operation, stats) in &operations {
            for (status, value) in &stats.total_by_status {
                push_labeled_metric(
                    out,
                    "snapshotter_snapshot_operation_total",
                    &[(*operation, "snapshot_operation"), (*status, "status")],
                    *value,
                );
            }
        }

        out.push_str("# HELP snapshotter_snapshot_operation_inflight Snapshotter gRPC operations currently in flight.\n");
        out.push_str("# TYPE snapshotter_snapshot_operation_inflight gauge\n");
        for (operation, stats) in &operations {
            push_labeled_metric(
                out,
                "snapshotter_snapshot_operation_inflight",
                &[(*operation, "snapshot_operation")],
                stats.in_flight,
            );
        }

        out.push_str("# HELP snapshotter_snapshot_operation_elapsed_milliseconds The elapsed time for snapshot events.\n");
        out.push_str("# TYPE snapshotter_snapshot_operation_elapsed_milliseconds histogram\n");
        for (operation, stats) in &operations {
            for (idx, bucket) in SNAPSHOT_DURATION_BUCKETS_MS.iter().enumerate() {
                push_labeled_metric(
                    out,
                    "snapshotter_snapshot_operation_elapsed_milliseconds_bucket",
                    &[
                        (*operation, "snapshot_operation"),
                        (bucket_label(*bucket), "le"),
                    ],
                    stats.duration_buckets[idx],
                );
            }
            push_labeled_metric(
                out,
                "snapshotter_snapshot_operation_elapsed_milliseconds_bucket",
                &[(*operation, "snapshot_operation"), ("+Inf", "le")],
                stats.duration_count,
            );
            push_labeled_metric_f64(
                out,
                "snapshotter_snapshot_operation_elapsed_milliseconds_sum",
                &[(*operation, "snapshot_operation")],
                stats.duration_sum_ms,
            );
            push_labeled_metric(
                out,
                "snapshotter_snapshot_operation_elapsed_milliseconds_count",
                &[(*operation, "snapshot_operation")],
                stats.duration_count,
            );
        }
    }

    fn render_process_metrics(&self, out: &mut String) {
        let process = ProcessMetrics::collect(self.started_at.elapsed());
        push_help_gauge(
            out,
            "snapshotter_run_time_seconds",
            "Running time of snapshotter from starting.",
        );
        push_metric_f64(
            out,
            "snapshotter_run_time_seconds",
            process.run_time_seconds,
        );
        push_help_gauge(out, "snapshotter_fd_counts", "Fd counts of snapshotter.");
        push_metric(out, "snapshotter_fd_counts", process.fd_count);
        push_help_gauge(
            out,
            "snapshotter_thread_counts",
            "Thread counts of snapshotter.",
        );
        push_metric(out, "snapshotter_thread_counts", process.thread_count);
        push_help_gauge(
            out,
            "snapshotter_memory_usage_kilobytes",
            "Memory usage (RSS) of snapshotter.",
        );
        push_metric(out, "snapshotter_memory_usage_kilobytes", process.rss_kib);
        push_help_gauge(
            out,
            "snapshotter_cpu_user_time_seconds",
            "CPU time of snapshotter in user.",
        );
        push_metric_f64(
            out,
            "snapshotter_cpu_user_time_seconds",
            process.cpu_user_seconds,
        );
        push_help_gauge(
            out,
            "snapshotter_cpu_system_time_seconds",
            "CPU time of snapshotter in system.",
        );
        push_metric_f64(
            out,
            "snapshotter_cpu_system_time_seconds",
            process.cpu_system_seconds,
        );
        push_help_gauge(
            out,
            "snapshotter_cpu_usage_percentage",
            "CPU usage percentage of snapshotter.",
        );
        push_metric_f64(out, "snapshotter_cpu_usage_percentage", 0.0);
    }

    fn render_cache_metrics(&self, out: &mut String, cache: CacheMetricSnapshot) {
        push_help_gauge(
            out,
            "snapshotter_cache_usage_kilobytes",
            "Disk usage of snapshotter local cache.",
        );
        push_metric(
            out,
            "snapshotter_cache_usage_kilobytes",
            cache.total_bytes / 1024,
        );
        out.push_str("# HELP snapshotter_cache_blobs_deleted_total Total number of cache blobs deleted during cleanup.\n");
        out.push_str("# TYPE snapshotter_cache_blobs_deleted_total counter\n");
        push_metric(
            out,
            "snapshotter_cache_blobs_deleted_total",
            cache.deleted_blobs,
        );
        push_help_gauge(
            out,
            "snapshotter_cache_blobs_in_use",
            "Number of cache blobs currently in use by running daemons.",
        );
        push_metric(out, "snapshotter_cache_blobs_in_use", cache.blobs_in_use);
        out.push_str("# HELP snapshotter_cache_blob_deletion_errors_total Total number of errors encountered while deleting cache blobs.\n");
        out.push_str("# TYPE snapshotter_cache_blob_deletion_errors_total counter\n");
        push_metric(
            out,
            "snapshotter_cache_blob_deletion_errors_total",
            cache.deletion_errors,
        );
    }
}

impl SnapshotOperationTimer {
    pub fn finish(mut self, status: &'static str) {
        self.finished = true;
        self.metrics
            .finish_snapshot_operation(self.operation, status, self.started_at.elapsed());
    }
}

impl Drop for SnapshotOperationTimer {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics.cancel_snapshot_operation(self.operation);
        }
    }
}

impl Default for SnapshotOperationStats {
    fn default() -> Self {
        Self {
            in_flight: 0,
            total_by_status: BTreeMap::new(),
            duration_count: 0,
            duration_sum_ms: 0.0,
            duration_buckets: [0; SNAPSHOT_DURATION_BUCKETS_MS.len()],
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ProcessMetrics {
    run_time_seconds: f64,
    fd_count: u64,
    thread_count: u64,
    rss_kib: u64,
    cpu_user_seconds: f64,
    cpu_system_seconds: f64,
}

impl ProcessMetrics {
    fn collect(run_time: Duration) -> Self {
        let (rss_kib, cpu_user_seconds, cpu_system_seconds) = platform_process_metrics();
        Self {
            run_time_seconds: run_time.as_secs_f64(),
            fd_count: count_dir_entries("/proc/self/fd"),
            thread_count: count_dir_entries("/proc/self/task"),
            rss_kib,
            cpu_user_seconds,
            cpu_system_seconds,
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_process_metrics() -> (u64, f64, f64) {
    let (user, system) = linux_cpu_seconds();
    (linux_rss_kib(), user, system)
}

#[cfg(not(target_os = "linux"))]
fn platform_process_metrics() -> (u64, f64, f64) {
    (0, 0.0, 0.0)
}

#[cfg(target_os = "linux")]
fn linux_rss_kib() -> u64 {
    let Ok(statm) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let Some(resident_pages) = statm
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return 0;
    };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return 0;
    }
    resident_pages.saturating_mul(page_size as u64) / 1024
}

#[cfg(target_os = "linux")]
fn linux_cpu_seconds() -> (f64, f64) {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return (0.0, 0.0);
    };
    let Some(close) = stat.rfind(')') else {
        return (0.0, 0.0);
    };
    let fields = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
    let user_ticks = fields
        .get(11)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let system_ticks = fields
        .get(12)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_second <= 0 {
        return (0.0, 0.0);
    }
    (
        user_ticks as f64 / ticks_per_second as f64,
        system_ticks as f64 / ticks_per_second as f64,
    )
}

fn count_dir_entries(path: &str) -> u64 {
    std::fs::read_dir(path)
        .map(|entries| entries.flatten().count() as u64)
        .unwrap_or(0)
}

fn bucket_label(bucket: f64) -> &'static str {
    match bucket {
        0.5 => "0.5",
        1.0 => "1",
        5.0 => "5",
        10.0 => "10",
        50.0 => "50",
        100.0 => "100",
        150.0 => "150",
        200.0 => "200",
        250.0 => "250",
        300.0 => "300",
        350.0 => "350",
        400.0 => "400",
        600.0 => "600",
        1000.0 => "1000",
        _ => "+Inf",
    }
}

fn push_help_gauge(out: &mut String, name: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
}

fn push_metric(out: &mut String, name: &str, value: u64) {
    let _ = writeln!(out, "{name} {value}");
}

fn push_metric_f64(out: &mut String, name: &str, value: f64) {
    let _ = writeln!(out, "{name} {:.6}", value);
}

fn push_labeled_metric(out: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    push_labeled_metric_value(out, name, labels, &value.to_string());
}

fn push_labeled_metric_f64(out: &mut String, name: &str, labels: &[(&str, &str)], value: f64) {
    push_labeled_metric_value(out, name, labels, &format!("{value:.6}"));
}

fn push_labeled_metric_value(out: &mut String, name: &str, labels: &[(&str, &str)], value: &str) {
    out.push_str(name);
    out.push('{');
    for (idx, (label_value, label_name)) in labels.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(label_name);
        out.push_str("=\"");
        out.push_str(&escape_label_value(label_value));
        out.push('"');
    }
    out.push_str("} ");
    out.push_str(value);
    out.push('\n');
}

fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_go_parity_snapshot_operation_metrics() {
        let metrics = Arc::new(SnapshotterMetrics::new());
        let timer = metrics.start_snapshot_operation("prepare");
        timer.finish("ok");

        let body = metrics.render_prometheus(CacheMetricSnapshot::default());
        assert!(body.contains("snapshotter_snapshot_operation_elapsed_milliseconds_bucket{snapshot_operation=\"prepare\",le=\"+Inf\"} 1"));
        assert!(body.contains(
            "snapshotter_snapshot_operation_total{snapshot_operation=\"prepare\",status=\"ok\"} 1"
        ));
        assert!(
            body.contains(
                "snapshotter_snapshot_operation_inflight{snapshot_operation=\"prepare\"} 0"
            )
        );
    }

    #[test]
    fn renders_go_parity_process_and_cache_metrics() {
        let metrics = SnapshotterMetrics::new();
        let body = metrics.render_prometheus(CacheMetricSnapshot {
            total_bytes: 4096,
            deleted_blobs: 2,
            deletion_errors: 1,
            blobs_in_use: 3,
        });
        assert!(body.contains("snapshotter_run_time_seconds"));
        assert!(body.contains("snapshotter_cache_usage_kilobytes 4"));
        assert!(body.contains("snapshotter_cache_blobs_deleted_total 2"));
        assert!(body.contains("snapshotter_cache_blob_deletion_errors_total 1"));
        assert!(body.contains("snapshotter_cache_blobs_in_use 3"));
    }
}
