// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! cgroup v2 controls for the snapshotter's existing service cgroup.
//!
//! The snapshotter runs as one systemd service together with its in-process
//! Nydus daemons. It must not move itself into a new cgroup: systemd owns the
//! service hierarchy and would then account the process incorrectly. Instead,
//! this module finds the process's current unified cgroup and applies the
//! operator-selected soft memory threshold there.

use anyhow::{Context, Result, bail};
#[cfg(any(target_os = "linux", test))]
use std::fs;
use std::path::PathBuf;
#[cfg(any(target_os = "linux", test))]
use std::path::{Component, Path};

#[cfg(target_os = "linux")]
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";
#[cfg(target_os = "linux")]
const PROC_SELF_CGROUP: &str = "/proc/self/cgroup";

/// Normalize a human-readable memory value to the byte value cgroup v2
/// expects in its memory controls.
///
/// `max` leaves the cgroup unconstrained. Binary units (`Ki`, `Mi`, `Gi`,
/// `Ti`) and decimal units (`K`, `M`, `G`, `T`) are accepted so a deployment
/// can use the same familiar notation as its systemd configuration.
pub fn normalize_memory_value(input: &str) -> Result<String> {
    let value = input.trim();
    if value == "max" {
        return Ok(value.to_string());
    }

    let digits_end = value
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(value.len());
    if digits_end == 0 {
        bail!("expected a byte count followed by an optional unit, or `max`");
    }

    let number = value[..digits_end]
        .parse::<u64>()
        .context("memory threshold is not an unsigned integer")?;
    let unit = value[digits_end..].to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "m" | "mb" => 1_000_000,
        "g" | "gb" => 1_000_000_000,
        "t" | "tb" => 1_000_000_000_000,
        "ki" | "kib" => 1 << 10,
        "mi" | "mib" => 1 << 20,
        "gi" | "gib" => 1 << 30,
        "ti" | "tib" => 1 << 40,
        _ => bail!("unsupported memory unit {unit:?}; use B, K/M/G/T, Ki/Mi/Gi/Ti, or `max`"),
    };
    let bytes = number
        .checked_mul(multiplier)
        .context("memory threshold exceeds the cgroup v2 u64 limit")?;
    Ok(bytes.to_string())
}

/// Set a memory control for the snapshotter's current cgroup.
///
/// `memory.high` is deliberately a soft threshold: the kernel reclaims from
/// this cgroup under pressure before it resorts to an OOM kill. The hard
/// `memory.max` control remains the responsibility of the service manager.
fn apply_memory_control(control: &str, value: &str) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        apply_memory_control_at(
            control,
            value,
            Path::new(PROC_SELF_CGROUP),
            Path::new(CGROUP_V2_ROOT),
        )
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = control;
        let _ = value;
        bail!("[snapshotter.cgroup] is supported only on Linux cgroup v2 hosts")
    }
}

/// Apply the soft `memory.high` threshold.
pub fn apply_memory_high(value: &str) -> Result<PathBuf> {
    apply_memory_control("memory.high", value)
}

/// Apply the hard `memory.max` limit.
pub fn apply_memory_max(value: &str) -> Result<PathBuf> {
    apply_memory_control("memory.max", value)
}

#[cfg(any(target_os = "linux", test))]
fn apply_memory_control_at(
    control: &str,
    value: &str,
    proc_cgroup: &Path,
    cgroup_root: &Path,
) -> Result<PathBuf> {
    let relative = current_unified_cgroup(proc_cgroup)?;
    let target = cgroup_root.join(relative).join(control);
    let value = normalize_memory_value(value)?;
    fs::write(&target, &value).with_context(|| format!("write {value} to {}", target.display()))?;
    Ok(target)
}

#[cfg(any(target_os = "linux", test))]
fn current_unified_cgroup(proc_cgroup: &Path) -> Result<PathBuf> {
    let contents = fs::read_to_string(proc_cgroup)
        .with_context(|| format!("read {}", proc_cgroup.display()))?;
    let path = contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("cgroup v2 unified entry `0::` is missing")?;

    let mut relative = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                bail!("cgroup v2 path {path:?} contains an unsafe component")
            }
        }
    }
    Ok(relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn normalizes_memory_high_values() {
        assert_eq!(normalize_memory_value("512Mi").unwrap(), "536870912");
        assert_eq!(normalize_memory_value("2G").unwrap(), "2000000000");
        assert_eq!(normalize_memory_value("max").unwrap(), "max");
        assert!(normalize_memory_value("512what").is_err());
        assert!(normalize_memory_value("-1Mi").is_err());
    }

    #[test]
    fn writes_to_the_current_unified_cgroup() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nydus-cgroup-test-{nonce}"));
        let proc_cgroup = root.join("proc-self-cgroup");
        let service = root.join("system.slice/containerd-nydus.service");
        fs::create_dir_all(&service).unwrap();
        fs::write(&proc_cgroup, "0::/system.slice/containerd-nydus.service\n").unwrap();
        fs::write(service.join("memory.high"), "max").unwrap();
        fs::write(service.join("memory.max"), "max").unwrap();

        let target = apply_memory_control_at("memory.high", "512Mi", &proc_cgroup, &root).unwrap();
        assert_eq!(target, service.join("memory.high"));
        assert_eq!(fs::read_to_string(target).unwrap(), "536870912");

        let target = apply_memory_control_at("memory.max", "2Gi", &proc_cgroup, &root).unwrap();
        assert_eq!(target, service.join("memory.max"));
        assert_eq!(fs::read_to_string(target).unwrap(), "2147483648");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unsafe_cgroup_paths() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nydus-cgroup-proc-{nonce}"));
        fs::write(&path, "0::/system.slice/../escape\n").unwrap();
        assert!(current_unified_cgroup(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
