// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Kernel and system capability probe.
//!
//! Determines which filesystem driver (fanotify, fusedev, blockdev) is viable
//! on the current host. The probe checks:
//! - Kernel version (for fanotify: ≥ 6.14)
//! - `FAN_CLASS_PRE_CONTENT` / `FAN_PRE_ACCESS` support
//! - EROFS module availability
//! - `/dev/fuse` availability
//! - Linux capabilities (`CAP_SYS_ADMIN`, etc.)
//! - cgroup v2 delegation

use crate::config::{FsDriverEntry, FsDriverSelectionPolicy, FsDriverType};
use anyhow::{Result, bail};
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

/// Result of a capability probe for a single driver.
#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub driver_type: FsDriverType,
    pub available: bool,
    pub reason: String,
}

/// Probe all configured filesystem drivers and return results in priority order.
///
/// The first driver that passes the probe is selected as the active driver.
pub fn probe_drivers(drivers: &[FsDriverEntry]) -> Vec<ProbeResult> {
    // Best-effort load erofs once before per-driver probing so both
    // fanotify and blockdev see it. Distros that compile erofs as a
    // module (Raspberry Pi OS' upstream kernels do — `CONFIG_EROFS_FS=m`)
    // leave it unloaded until the first mount, which makes the
    // `has_filesystem("erofs")` check at startup fall through to fusedev
    // even though the kernel fully supports it. modprobe is idempotent;
    // failures (missing binary, missing CAP_SYS_MODULE, already
    // built-in) are silent.
    ensure_erofs_loaded_once();
    drivers.iter().map(probe_single).collect()
}

/// Probe configured filesystem drivers and promote the first available driver
/// to the front of the config list.
///
/// The rest of the list is preserved for diagnostics/future fallback, but all
/// runtime paths that read `fs_drivers.first()` now observe the actual selected
/// driver rather than the static preference order from the TOML file.
pub fn probe_and_promote_driver(
    drivers: &mut Vec<FsDriverEntry>,
    policy: FsDriverSelectionPolicy,
) -> (Vec<ProbeResult>, Option<FsDriverType>) {
    apply_driver_selection_policy(drivers, policy);
    let results = probe_drivers(drivers);
    let selected = promote_selected_driver(drivers, &results);
    (results, selected)
}

/// Normalize the configured candidate list before probing.
pub fn apply_driver_selection_policy(
    drivers: &mut [FsDriverEntry],
    policy: FsDriverSelectionPolicy,
) {
    if policy == FsDriverSelectionPolicy::Auto {
        drivers.sort_by_key(|entry| driver_auto_rank(&entry.driver_type));
    }
}

/// Select the best available driver from the probe results.
pub fn select_driver(results: &[ProbeResult]) -> Option<&FsDriverType> {
    select_driver_index(results).and_then(|idx| results.get(idx).map(|r| &r.driver_type))
}

/// Promote the first available driver from `results` to index 0 in `drivers`.
pub fn promote_selected_driver(
    drivers: &mut Vec<FsDriverEntry>,
    results: &[ProbeResult],
) -> Option<FsDriverType> {
    let idx = select_driver_index(results)?;
    if idx >= drivers.len() {
        return None;
    }
    let selected = drivers.remove(idx);
    let driver_type = selected.driver_type.clone();
    drivers.insert(0, selected);
    Some(driver_type)
}

fn select_driver_index(results: &[ProbeResult]) -> Option<usize> {
    results.iter().position(|r| r.available)
}

fn driver_auto_rank(driver: &FsDriverType) -> u8 {
    match driver {
        // Fanotify pre-content has the best production path when available.
        FsDriverType::Fanotify => 0,
        // Blockdev loop/EROFS avoids userspace FUSE once a host can mount it.
        FsDriverType::Blockdev => 1,
        // Fusedev remains the safest compatibility fallback.
        FsDriverType::Fusedev => 2,
    }
}

fn probe_single(entry: &FsDriverEntry) -> ProbeResult {
    match entry.driver_type {
        FsDriverType::Fanotify => probe_fanotify(entry),
        FsDriverType::Fusedev => probe_fusedev(entry),
        FsDriverType::Blockdev => probe_blockdev(entry),
    }
}

fn probe_fanotify(entry: &FsDriverEntry) -> ProbeResult {
    // 1. Check kernel version ≥ 6.14
    if let Err(e) = check_kernel_version("6.14") {
        return ProbeResult {
            driver_type: FsDriverType::Fanotify,
            available: false,
            reason: format!("kernel version check failed: {}", e),
        };
    }

    // 2. Check EROFS module
    if !has_filesystem("erofs") {
        return ProbeResult {
            driver_type: FsDriverType::Fanotify,
            available: false,
            reason: "EROFS filesystem module not available".to_string(),
        };
    }

    // 3. Check required capabilities
    if !has_caps(&entry.require_caps) {
        return ProbeResult {
            driver_type: FsDriverType::Fanotify,
            available: false,
            reason: format!("missing required capabilities: {:?}", entry.require_caps),
        };
    }

    // 4. Try opening a fanotify fd with FAN_CLASS_PRE_CONTENT
    if let Err(e) = try_fanotify_init() {
        return ProbeResult {
            driver_type: FsDriverType::Fanotify,
            available: false,
            reason: format!("fanotify init failed: {}", e),
        };
    }

    info!("fanotify driver probe passed");
    ProbeResult {
        driver_type: FsDriverType::Fanotify,
        available: true,
        reason: "all probes passed".to_string(),
    }
}

fn probe_fusedev(entry: &FsDriverEntry) -> ProbeResult {
    // Check /dev/fuse
    if !Path::new("/dev/fuse").exists() {
        return ProbeResult {
            driver_type: FsDriverType::Fusedev,
            available: false,
            reason: "/dev/fuse not found".to_string(),
        };
    }

    // Check FUSE module
    if !has_filesystem("fuse") {
        warn!(
            "FUSE filesystem module not listed in /proc/filesystems, but /dev/fuse exists; attempting anyway"
        );
    }

    // Check required capabilities
    if !has_caps(&entry.require_caps) {
        return ProbeResult {
            driver_type: FsDriverType::Fusedev,
            available: false,
            reason: format!("missing required capabilities: {:?}", entry.require_caps),
        };
    }

    info!("fusedev driver probe passed");
    ProbeResult {
        driver_type: FsDriverType::Fusedev,
        available: true,
        reason: "all probes passed".to_string(),
    }
}

fn probe_blockdev(entry: &FsDriverEntry) -> ProbeResult {
    probe_blockdev_platform(entry)
}

#[cfg(target_os = "linux")]
fn probe_blockdev_platform(entry: &FsDriverEntry) -> ProbeResult {
    if !has_filesystem("erofs") {
        return ProbeResult {
            driver_type: FsDriverType::Blockdev,
            available: false,
            reason: "EROFS filesystem module not available".to_string(),
        };
    }
    if !has_caps(&entry.require_caps) {
        return ProbeResult {
            driver_type: FsDriverType::Blockdev,
            available: false,
            reason: format!("missing required capabilities: {:?}", entry.require_caps),
        };
    }

    match entry.mode.as_deref().unwrap_or("loop") {
        "loop" => {
            if !Path::new("/dev/loop-control").exists()
                && !Path::new("/sys/module/loop").exists()
                && !Path::new("/dev/loop0").exists()
            {
                return ProbeResult {
                    driver_type: FsDriverType::Blockdev,
                    available: false,
                    reason: "loop device support not available".to_string(),
                };
            }
            info!("blockdev loop driver probe passed");
            ProbeResult {
                driver_type: FsDriverType::Blockdev,
                available: true,
                reason: "erofs and loop device probes passed".to_string(),
            }
        }
        "nbd" => ProbeResult {
            driver_type: FsDriverType::Blockdev,
            available: false,
            reason: "blockdev nbd mode requires explicit /dev/nbd allocation and is not enabled for auto selection".to_string(),
        },
        "uffd" => ProbeResult {
            driver_type: FsDriverType::Blockdev,
            available: false,
            reason: "blockdev uffd mode is for VM handoff and is not a host mount driver".to_string(),
        },
        other => ProbeResult {
            driver_type: FsDriverType::Blockdev,
            available: false,
            reason: format!("unsupported blockdev mode {other}"),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_blockdev_platform(_entry: &FsDriverEntry) -> ProbeResult {
    ProbeResult {
        driver_type: FsDriverType::Blockdev,
        available: false,
        reason: "blockdev requires Linux EROFS and loop device support".to_string(),
    }
}

/// Check that the current kernel version is at least `min_version` (semver "major.minor.patch").
#[cfg(target_os = "linux")]
fn check_kernel_version(min_version: &str) -> Result<()> {
    let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::uname(&mut buf) };
    if ret < 0 {
        bail!("failed to call uname: {}", std::io::Error::last_os_error());
    }
    let release = unsafe { std::ffi::CStr::from_ptr(buf.release.as_ptr()) }
        .to_string_lossy()
        .to_string();
    // Kernel version strings may have suffixes like "6.14.0-rc1-generic".
    let release_base = release.split('-').next().unwrap_or(&release);
    let parts: Vec<u32> = release_base
        .split('.')
        .filter_map(|p: &str| p.parse().ok())
        .collect();
    let min_parts: Vec<u32> = min_version
        .split('.')
        .filter_map(|p: &str| p.parse().ok())
        .collect();

    for (i, &min) in min_parts.iter().enumerate() {
        let cur = parts.get(i).copied().unwrap_or(0);
        if cur > min {
            break;
        }
        if cur < min {
            bail!("kernel version {} < required {}", release_base, min_version);
        }
    }
    debug!(current = %release_base, required = %min_version, "kernel version check passed");
    Ok(())
}

/// On non-Linux, kernel version checks always fail (fanotify/fusedev are Linux-only).
#[cfg(not(target_os = "linux"))]
fn check_kernel_version(_min_version: &str) -> Result<()> {
    bail!("kernel version check is only supported on Linux");
}

/// Check whether a filesystem type is listed in `/proc/filesystems`.
fn has_filesystem(fs_name: &str) -> bool {
    fs::read_to_string("/proc/filesystems")
        .map(|content| content.contains(fs_name))
        .unwrap_or(false)
}

/// Best-effort `modprobe erofs` at startup. Only runs once per process
/// (cached in `EROFS_MODPROBE`), skips when erofs is already listed in
/// `/proc/filesystems` (built-in or already-loaded), and silently
/// tolerates a missing modprobe binary / missing CAP_SYS_MODULE. The
/// fanotify + blockdev probes downstream still do their own
/// `has_filesystem("erofs")` check, so a failure here just keeps the
/// pre-existing behaviour.
fn ensure_erofs_loaded_once() {
    use std::sync::Once;
    static EROFS_MODPROBE: Once = Once::new();
    EROFS_MODPROBE.call_once(ensure_erofs_loaded_inner);
}

#[cfg(target_os = "linux")]
fn ensure_erofs_loaded_inner() {
    if has_filesystem("erofs") {
        return; // already loaded or built-in
    }
    // Try the usual locations. Some minimal images don't put
    // modprobe on PATH for non-interactive systemd units.
    for binary in ["modprobe", "/sbin/modprobe", "/usr/sbin/modprobe"] {
        match std::process::Command::new(binary).arg("erofs").status() {
            Ok(status) if status.success() => {
                info!("loaded erofs kernel module via {binary}");
                return;
            }
            Ok(status) => {
                debug!(%binary, code = status.code(), "modprobe erofs returned non-zero");
            }
            Err(e) => {
                debug!(%binary, error = %e, "modprobe erofs invocation failed");
            }
        }
    }
    debug!(
        "erofs not loadable via modprobe; \
         fanotify + blockdev probes will fall through to fusedev \
         unless erofs is autoloaded out-of-band"
    );
}

#[cfg(not(target_os = "linux"))]
fn ensure_erofs_loaded_inner() {}

/// Name -> bit table for Linux capabilities, from `linux/capability.h`.
/// Index into this table is the bit position in the `CapEff`/`CapPrm`/etc.
/// bitmasks reported by `/proc/self/status`.
const CAPABILITY_BITS: &[(&str, u32)] = &[
    ("CHOWN", 0),
    ("DAC_OVERRIDE", 1),
    ("DAC_READ_SEARCH", 2),
    ("FOWNER", 3),
    ("FSETID", 4),
    ("KILL", 5),
    ("SETGID", 6),
    ("SETUID", 7),
    ("SETPCAP", 8),
    ("LINUX_IMMUTABLE", 9),
    ("NET_BIND_SERVICE", 10),
    ("NET_BROADCAST", 11),
    ("NET_ADMIN", 12),
    ("NET_RAW", 13),
    ("IPC_LOCK", 14),
    ("IPC_OWNER", 15),
    ("SYS_MODULE", 16),
    ("SYS_RAWIO", 17),
    ("SYS_CHROOT", 18),
    ("SYS_PTRACE", 19),
    ("SYS_PACCT", 20),
    ("SYS_ADMIN", 21),
    ("SYS_BOOT", 22),
    ("SYS_NICE", 23),
    ("SYS_RESOURCE", 24),
    ("SYS_TIME", 25),
    ("SYS_TTY_CONFIG", 26),
    ("MKNOD", 27),
    ("LEASE", 28),
    ("AUDIT_WRITE", 29),
    ("AUDIT_CONTROL", 30),
    ("SETFCAP", 31),
    ("MAC_OVERRIDE", 32),
    ("MAC_ADMIN", 33),
    ("SYSLOG", 34),
    ("WAKE_ALARM", 35),
    ("BLOCK_SUSPEND", 36),
    ("AUDIT_READ", 37),
    ("PERFMON", 38),
    ("BPF", 39),
    ("CHECKPOINT_RESTORE", 40),
];

/// Normalize a capability name from config into the bare `linux/capability.h`
/// spelling used by [`CAPABILITY_BITS`]: uppercase, `CAP_` prefix stripped.
fn normalize_cap_name(name: &str) -> String {
    let upper = name.trim().to_ascii_uppercase();
    upper.strip_prefix("CAP_").unwrap_or(&upper).to_string()
}

/// Look up the bit position for a capability name (case-insensitive, with or
/// without the `CAP_` prefix). Returns `None` for unknown names.
fn cap_bit(name: &str) -> Option<u32> {
    let normalized = normalize_cap_name(name);
    CAPABILITY_BITS
        .iter()
        .find(|(cap_name, _)| *cap_name == normalized)
        .map(|(_, bit)| *bit)
}

/// Parse the `CapEff:` line out of `/proc/self/status` content and check
/// that every capability in `caps` is set in the effective bitmask.
///
/// This is the pure, unit-testable core of [`has_caps`]. Semantics:
/// - If the `CapEff:` line is missing or unparsable, assume capabilities are
///   present (permissive fallback; the caller logs a `warn!` for this case).
/// - If any name in `caps` doesn't match a known capability, treat it as
///   not satisfied (return `false`); the caller logs a `warn!` identifying
///   the offending name so a config typo doesn't silently pass.
/// - Otherwise, return `true` only if every requested capability's bit is
///   set in `CapEff`.
fn has_caps_in_status(status: &str, caps: &[String]) -> bool {
    if caps.is_empty() {
        return true;
    }

    let cap_eff_hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(|rest| rest.trim());

    let Some(hex) = cap_eff_hex else {
        warn!(
            "no CapEff line in /proc/self/status; assuming required capabilities {:?} are present",
            caps
        );
        return true;
    };

    let Ok(mask) = u64::from_str_radix(hex, 16) else {
        warn!(
            hex = %hex,
            "unparsable CapEff value in /proc/self/status; assuming required capabilities {:?} are present",
            caps
        );
        return true;
    };

    for cap in caps {
        match cap_bit(cap) {
            Some(bit) => {
                if mask & (1u64 << bit) == 0 {
                    debug!(capability = %cap, "required capability not set in CapEff");
                    return false;
                }
            }
            None => {
                warn!(capability = %cap, "unknown capability name in require_caps; treating as not satisfied");
                return false;
            }
        }
    }
    true
}

/// Check whether the current process holds all required Linux capabilities.
///
/// Reads the effective capability bitmask (`CapEff`) from
/// `/proc/self/status` and checks it against `caps` via
/// [`has_caps_in_status`]. If `/proc/self/status` itself can't be read
/// (e.g. a container without `/proc` mounted), this degrades permissively
/// and assumes the capabilities are present; the actual fanotify/fuse calls
/// will fail at runtime if we actually lack them.
fn has_caps(caps: &[String]) -> bool {
    if caps.is_empty() {
        return true;
    }
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => has_caps_in_status(&status, caps),
        Err(e) => {
            warn!(
                error = %e,
                "could not read /proc/self/status; assuming required capabilities {:?} are present",
                caps
            );
            true
        }
    }
}

/// Try to open a fanotify file descriptor with `FAN_CLASS_PRE_CONTENT`.
/// The constant value MUST match `service/src/fanotify_sys.rs::FAN_CLASS_PRE_CONTENT`
/// — the prod fanotify path uses that copy, and a drift here makes the
/// probe silently fail (kernel returns EINVAL on the undefined bit) on
/// every host even when the kernel fully supports pre-content marks.
/// See the `fan_class_pre_content_uapi_value` test below.
#[cfg(target_os = "linux")]
fn try_fanotify_init() -> Result<()> {
    // From include/uapi/linux/fanotify.h:
    //   FAN_CLASS_PRE_CONTENT = 0x00000008  (class bits in the lower byte)
    const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
    // event_f_flags: O_RDONLY (= 0) is all we need. Do NOT OR in
    // `libc::O_LARGEFILE` — on aarch64-musl the libc crate defines it
    // as 0x8000, but the aarch64 Linux UAPI puts O_NOFOLLOW at 0x8000
    // and O_LARGEFILE at 0x20000, so the kernel sees O_NOFOLLOW (not
    // in `FANOTIFY_INIT_FD_FLAGS`) and `fanotify_init` returns EINVAL
    // on every aarch64 host. LFS is implicit on 64-bit Linux anyway.
    // Same fix mirrored in `service/src/fanotify.rs::FanotifyHandler::new`.
    const O_RDONLY: i32 = 0;

    let fd = unsafe { libc::fanotify_init(FAN_CLASS_PRE_CONTENT, O_RDONLY as u32) };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        bail!("fanotify_init(FAN_CLASS_PRE_CONTENT) failed: {}", err);
    }

    // Close the fd immediately; we only needed to verify the kernel supports it.
    unsafe {
        libc::close(fd);
    }
    Ok(())
}

#[cfg(test)]
mod fanotify_const_tests {
    /// Pin the on-the-wire value of `FAN_CLASS_PRE_CONTENT`. Mirrors the
    /// assertion in `service/src/fanotify_sys.rs` — if the kernel UAPI
    /// ever renumbers this (extremely unlikely), both copies and this
    /// test must change together. Keeps the snapshotter's probe in
    /// lockstep with the prod path it gates.
    #[test]
    fn fan_class_pre_content_uapi_value() {
        const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
        assert_eq!(FAN_CLASS_PRE_CONTENT, 0x0000_0008);
    }
}

/// On non-Linux, fanotify is never available.
#[cfg(not(target_os = "linux"))]
fn try_fanotify_init() -> Result<()> {
    bail!("fanotify is only available on Linux");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version_parsing() {
        // These tests run on whatever kernel the CI host has; just ensure no panic.
        let _ = check_kernel_version("5.4.0");
        let _ = check_kernel_version("6.14.0");
    }

    #[test]
    fn filesystem_check() {
        // "ext4" should be available on most Linux hosts.
        // This test is best-effort and may fail in containers without /proc.
        let _ = has_filesystem("ext4");
    }

    #[test]
    fn probe_drivers_returns_results() {
        let drivers = vec![
            FsDriverEntry {
                driver_type: FsDriverType::Fanotify,
                min_kernel: Some("6.14".to_string()),
                require_caps: vec!["CAP_SYS_ADMIN".to_string()],
                mode: None,
            },
            FsDriverEntry {
                driver_type: FsDriverType::Fusedev,
                min_kernel: None,
                require_caps: vec![],
                mode: None,
            },
        ];
        let results = probe_drivers(&drivers);
        assert_eq!(results.len(), 2);
        // At least fusedev should be available on most Linux hosts.
        assert!(
            results
                .iter()
                .any(|r| r.driver_type == FsDriverType::Fusedev)
        );
    }

    #[test]
    fn promote_selected_driver_moves_first_available_to_front() {
        let mut drivers = vec![
            FsDriverEntry {
                driver_type: FsDriverType::Fanotify,
                min_kernel: Some("6.14".to_string()),
                require_caps: vec!["CAP_SYS_ADMIN".to_string()],
                mode: None,
            },
            FsDriverEntry {
                driver_type: FsDriverType::Fusedev,
                min_kernel: None,
                require_caps: vec![],
                mode: None,
            },
            FsDriverEntry {
                driver_type: FsDriverType::Blockdev,
                min_kernel: None,
                require_caps: vec![],
                mode: Some("loop".to_string()),
            },
        ];
        let results = vec![
            ProbeResult {
                driver_type: FsDriverType::Fanotify,
                available: false,
                reason: "kernel too old".to_string(),
            },
            ProbeResult {
                driver_type: FsDriverType::Fusedev,
                available: true,
                reason: "ok".to_string(),
            },
            ProbeResult {
                driver_type: FsDriverType::Blockdev,
                available: true,
                reason: "ok".to_string(),
            },
        ];

        let selected = promote_selected_driver(&mut drivers, &results);

        assert_eq!(selected, Some(FsDriverType::Fusedev));
        assert_eq!(drivers[0].driver_type, FsDriverType::Fusedev);
        assert_eq!(drivers[1].driver_type, FsDriverType::Fanotify);
        assert_eq!(drivers[2].driver_type, FsDriverType::Blockdev);
    }

    #[test]
    fn auto_policy_sorts_candidates_by_production_preference() {
        let mut drivers = vec![
            FsDriverEntry {
                driver_type: FsDriverType::Fusedev,
                min_kernel: None,
                require_caps: vec![],
                mode: None,
            },
            FsDriverEntry {
                driver_type: FsDriverType::Blockdev,
                min_kernel: None,
                require_caps: vec![],
                mode: Some("loop".to_string()),
            },
            FsDriverEntry {
                driver_type: FsDriverType::Fanotify,
                min_kernel: Some("6.14".to_string()),
                require_caps: vec!["CAP_SYS_ADMIN".to_string()],
                mode: None,
            },
        ];

        apply_driver_selection_policy(&mut drivers, FsDriverSelectionPolicy::Auto);

        assert_eq!(drivers[0].driver_type, FsDriverType::Fanotify);
        assert_eq!(drivers[1].driver_type, FsDriverType::Blockdev);
        assert_eq!(drivers[2].driver_type, FsDriverType::Fusedev);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn blockdev_probe_is_not_available_off_linux() {
        let entry = FsDriverEntry {
            driver_type: FsDriverType::Blockdev,
            min_kernel: None,
            require_caps: vec!["CAP_SYS_ADMIN".to_string()],
            mode: Some("loop".to_string()),
        };

        let result = probe_blockdev(&entry);

        assert!(!result.available);
        assert!(result.reason.contains("requires Linux"));
    }

    #[test]
    fn ordered_policy_preserves_user_configured_fallback_chain() {
        let mut drivers = vec![
            FsDriverEntry {
                driver_type: FsDriverType::Fusedev,
                min_kernel: None,
                require_caps: vec![],
                mode: None,
            },
            FsDriverEntry {
                driver_type: FsDriverType::Fanotify,
                min_kernel: Some("6.14".to_string()),
                require_caps: vec!["CAP_SYS_ADMIN".to_string()],
                mode: None,
            },
        ];

        apply_driver_selection_policy(&mut drivers, FsDriverSelectionPolicy::Ordered);

        assert_eq!(drivers[0].driver_type, FsDriverType::Fusedev);
        assert_eq!(drivers[1].driver_type, FsDriverType::Fanotify);
    }

    #[test]
    fn has_caps_in_status_empty_requirements_always_pass() {
        assert!(has_caps_in_status("", &[]));
    }

    #[test]
    fn has_caps_in_status_full_mask_grants_all_known_caps() {
        // Root's typical CapEff: all 41 defined capability bits set.
        let status = "Name:\tfoo\nCapEff:\t000001ffffffffff\n";
        assert!(has_caps_in_status(status, &["CAP_SYS_ADMIN".to_string()]));
        assert!(has_caps_in_status(
            status,
            &[
                "CAP_SYS_ADMIN".to_string(),
                "CAP_NET_ADMIN".to_string(),
                "CAP_CHECKPOINT_RESTORE".to_string()
            ]
        ));
    }

    #[test]
    fn has_caps_in_status_empty_mask_fails_sys_admin() {
        let status = "Name:\tfoo\nCapEff:\t0000000000000000\n";
        assert!(!has_caps_in_status(status, &["CAP_SYS_ADMIN".to_string()]));
    }

    #[test]
    fn has_caps_in_status_missing_line_is_permissive() {
        let status = "Name:\tfoo\nPid:\t1\n";
        assert!(has_caps_in_status(status, &["CAP_SYS_ADMIN".to_string()]));
    }

    #[test]
    fn has_caps_in_status_unparsable_line_is_permissive() {
        let status = "Name:\tfoo\nCapEff:\tnot-hex\n";
        assert!(has_caps_in_status(status, &["CAP_SYS_ADMIN".to_string()]));
    }

    #[test]
    fn has_caps_in_status_unknown_cap_name_fails() {
        // Only CAP_SYS_ADMIN's bit (21) is set; the unknown name must not
        // silently pass even though every *known* bit here is satisfied.
        let status = "Name:\tfoo\nCapEff:\t0000000000200000\n";
        assert!(!has_caps_in_status(
            status,
            &["CAP_NOT_A_REAL_CAP".to_string()]
        ));
    }

    #[test]
    fn has_caps_in_status_name_normalization() {
        // Only CAP_SYS_ADMIN's bit (21) is set.
        let status = "Name:\tfoo\nCapEff:\t0000000000200000\n";
        for variant in ["CAP_SYS_ADMIN", "cap_sys_admin", "sys_admin", "SYS_ADMIN"] {
            assert!(
                has_caps_in_status(status, &[variant.to_string()]),
                "variant {variant} should match CAP_SYS_ADMIN bit"
            );
        }
    }

    #[test]
    fn has_caps_in_status_partial_mask_missing_one_cap_fails() {
        // Only CAP_SYS_ADMIN's bit (21) is set; CAP_NET_ADMIN (bit 12) is not.
        let status = "Name:\tfoo\nCapEff:\t0000000000200000\n";
        assert!(!has_caps_in_status(
            status,
            &["CAP_SYS_ADMIN".to_string(), "CAP_NET_ADMIN".to_string()]
        ));
    }

    #[test]
    fn cap_bit_known_and_unknown_names() {
        assert_eq!(cap_bit("CAP_SYS_ADMIN"), Some(21));
        assert_eq!(cap_bit("sys_admin"), Some(21));
        assert_eq!(cap_bit("cap_chown"), Some(0));
        assert_eq!(cap_bit("CAP_CHECKPOINT_RESTORE"), Some(40));
        assert_eq!(cap_bit("not_a_cap"), None);
    }

    #[test]
    fn promote_selected_driver_keeps_config_when_none_available() {
        let mut drivers = vec![FsDriverEntry {
            driver_type: FsDriverType::Fanotify,
            min_kernel: Some("6.14".to_string()),
            require_caps: vec!["CAP_SYS_ADMIN".to_string()],
            mode: None,
        }];
        let original = drivers.clone();
        let results = vec![ProbeResult {
            driver_type: FsDriverType::Fanotify,
            available: false,
            reason: "unsupported".to_string(),
        }];

        assert_eq!(promote_selected_driver(&mut drivers, &results), None);
        assert_eq!(drivers[0].driver_type, original[0].driver_type);
        assert_eq!(drivers[0].min_kernel, original[0].min_kernel);
    }
}
