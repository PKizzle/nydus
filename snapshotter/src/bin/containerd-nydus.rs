// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Nydus containerd remote snapshotter binary.
//!
//! Single binary that embeds the nydusd daemon in-process and serves
//! containerd's proxy-plugin gRPC protocol.

// mimalloc global allocator: compio's completion I/O (gRPC + in-process daemon
// blob reads) is owned-buffer-per-op; mimalloc's thread-local pools cut the
// small-buffer allocation overhead.
// Disabled under Miri, which cannot call mimalloc's FFI (mi_malloc_aligned) and
// aborts even when just listing tests; fall back to Miri's own allocator.
#[cfg(not(miri))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Result;
use clap::Parser;
use futures::FutureExt;
use std::sync::Arc;
use tracing::{info, warn};

use nydus_snapshotter::config::{Profile, SnapshotterConfig};
use nydus_snapshotter::daemon::DaemonSupervisor;

/// Parse a deployment-profile string ("auto"/"k3s"/"containerd", case
/// insensitive) into a [`Profile`]. Mirrors the `#[serde(rename_all =
/// "lowercase")]` names the TOML `profile` field accepts, so the
/// `--profile`/`NYDUS_SNAPSHOTTER_PROFILE` override and the config file agree.
fn parse_profile(s: &str) -> Result<Profile, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(Profile::Auto),
        "k3s" => Ok(Profile::K3s),
        "containerd" => Ok(Profile::Containerd),
        other => Err(format!(
            "invalid profile {other:?}; expected one of: auto, k3s, containerd"
        )),
    }
}

/// Command-line arguments for the snapshotter.
///
/// Every override also reads a `NYDUS_SNAPSHOTTER_*` environment variable so the
/// binary is configurable in a container without a mounted config file. clap's
/// precedence applies: an explicit flag beats the env var, which beats the
/// default (and, for `--profile`, the TOML `profile` field).
#[derive(Parser, Debug)]
#[command(
    name = "containerd-nydus",
    about = "Nydus containerd remote snapshotter"
)]
struct Args {
    /// Path to the unified TOML configuration file.
    #[arg(short, long, env = "NYDUS_SNAPSHOTTER_CONFIG")]
    config: Option<String>,

    /// Override the gRPC socket address.
    #[arg(short, long, env = "NYDUS_SNAPSHOTTER_ADDRESS")]
    address: Option<String>,

    /// Override the root directory.
    #[arg(short, long, env = "NYDUS_SNAPSHOTTER_ROOT")]
    root: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(
        short,
        long,
        env = "NYDUS_SNAPSHOTTER_LOG_LEVEL",
        default_value = "info"
    )]
    log_level: String,

    /// Override the deployment profile (auto/k3s/containerd). Takes precedence
    /// over the TOML `[snapshotter].profile` field and is applied before
    /// profile resolution.
    #[arg(long, env = "NYDUS_SNAPSHOTTER_PROFILE", value_parser = parse_profile)]
    profile: Option<Profile>,
}

#[compio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
        )
        .init();

    // Surface panics from detached async tasks (e.g. the system-controller connection
    // handlers): the async runtime catches them, so without a hook they vanish silently
    // and only show up as a dropped/reset socket on the client side.
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        tracing::error!(location = %location, payload = %payload, "panic in snapshotter task");
        default_panic(info);
    }));

    info!(
        version = nydus_snapshotter::VERSION,
        "starting containerd-nydus snapshotter"
    );

    // Load configuration.
    let config = if let Some(path) = &args.config {
        let content = std::fs::read_to_string(path)?;
        toml::from_str::<SnapshotterConfig>(&content)?
    } else {
        // Use defaults.
        SnapshotterConfig::default()
    };

    // Apply CLI overrides.
    let mut config = config;
    if let Some(address) = args.address {
        config.snapshotter.address = std::path::PathBuf::from(address);
    }
    if let Some(root) = args.root {
        config.snapshotter.root = std::path::PathBuf::from(root);
    }
    // Override the TOML `[snapshotter].profile` from --profile /
    // NYDUS_SNAPSHOTTER_PROFILE BEFORE resolve_profile runs, so the precedence
    // is: explicit flag/env > TOML profile field > default auto.
    if let Some(profile) = args.profile {
        config.snapshotter.profile = profile;
    }

    // Resolve the deployment profile (auto/k3s/containerd) IN MEMORY: fills any
    // profile- or preset-sensitive field the operator left unset (containerd
    // socket + content root, peer-mirror preset + endpoint + cert paths).
    // Explicit TOML values always win. Runs after CLI overrides and before the
    // driver probe / DaemonSupervisor. Never writes config files.
    let resolved_profile = match config.resolve_profile() {
        Ok(rp) => rp,
        Err(e) => anyhow::bail!("profile resolution failed: {e}"),
    };
    info!(
        profile = ?resolved_profile.profile,
        reason = %resolved_profile.reason,
        containerd_socket = %config.snapshotter.containerd.address().display(),
        content_root = %config.snapshotter.containerd.content_root().display(),
        peer_mirror_preset = ?config.snapshotter.peer_mirror.preset,
        "resolved deployment profile"
    );

    // Reject backend configurations the in-process daemon cannot honour (e.g.
    // an orphan [backends.localfs], or more than one pull backend) instead of
    // silently ignoring them.
    if let Err(e) = config.validate() {
        anyhow::bail!("configuration error: {e}");
    }

    // Fail fast with an actionable message if auto_zran is on but the resolved
    // containerd socket is missing — otherwise this surfaces as a late,
    // opaque gRPC connect error deep in the conversion path.
    if config.snapshotter.auto_zran.enable {
        let sock = config.snapshotter.containerd.address();
        if !sock.exists() {
            anyhow::bail!(
                "auto_zran is enabled but the containerd socket {} does not exist. \
                 Start containerd/k3s, or fix [snapshotter.containerd].address / \
                 [snapshotter].profile.",
                sock.display()
            );
        }
    }

    // Probe filesystem drivers and promote the selected one to the front of
    // `fs_drivers` — same call convention as `grpc::serve` (grpc/mod.rs)
    // — so the config we hand to `DaemonSupervisor` and `serve_with_supervisor`
    // below agrees with what `grpc::serve` would select for the same config.
    // Must run before `config` is cloned into the supervisor:
    // `serve_with_supervisor` assumes its caller already normalized the driver
    // list (see its doc comment).
    let work_dir = config.snapshotter.cache.work_dir.clone();
    let (probe_results, selected) = nydus_snapshotter::probe::probe_and_promote_driver(
        &mut config.snapshotter.fs_drivers,
        config.snapshotter.fs_driver_policy,
        Some(&work_dir),
    );
    for result in &probe_results {
        info!(
            driver = ?result.driver_type,
            available = result.available,
            reason = %result.reason,
            "driver probe result"
        );
    }
    match selected {
        Some(driver) => info!(driver = ?driver, "selected filesystem driver"),
        None => anyhow::bail!(
            "no viable filesystem driver found; fanotify, fusedev, and blockdev all failed probe"
        ),
    }

    // Start the gRPC server with a shared supervisor so signal handlers can
    // tear running nydus daemons down on shutdown.
    let supervisor = Arc::new(DaemonSupervisor::new(config.clone()));

    // Take over any mounts whose `/dev/fuse` fds systemd preserved across our
    // restart (or `kill -9`) so running containers keep their filesystem without
    // a remount. No-op when not run under a `Type=notify` unit with a fd store.
    let restored = supervisor.restore_from_store().await;
    if restored > 0 {
        info!(
            restored,
            "resumed nydus daemons from preserved fuse descriptors"
        );
    }

    // Open the fjall snapshot store HERE — not inside the server task — so the
    // shutdown path below can fsync the journal with a known-good handle even
    // when systemd is about to `kill -9` us on the failover path. If the store
    // lived inside the server task, runtime drop could cancel that task with
    // the journal's last batch still buffered, costing us the in-flight
    // snapshot metadata on the next start.
    let store = nydus_snapshotter::grpc::open_store_for_config(&config)?;
    let shutdown_store = store.clone();

    let shutdown_supervisor = supervisor.clone();
    let server = compio::runtime::spawn(async move {
        nydus_snapshotter::grpc::serve_with_supervisor(config, supervisor, store).await
    });

    // Notify systemd we finished starting (required for `Type=notify`). No-op
    // without a notify socket.
    if let Err(e) = nydus_snapshotter::fdstore::notify_ready() {
        warn!(error = %e, "sd_notify READY failed");
    }

    // Graceful shutdown on SIGTERM/SIGINT. `signal-hook` is runtime-agnostic; a
    // dedicated thread blocks on the signal and notifies the compio main over an
    // async channel (compio runs thread-per-core, so signals are handled off the
    // runtime thread).
    let (shutdown_tx, shutdown_rx) = async_channel::bounded::<()>(1);
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ])?;
    std::thread::spawn(move || {
        if signals.forever().next().is_some() {
            let _ = shutdown_tx.try_send(());
        }
    });

    futures::select! {
        _ = shutdown_rx.recv().fuse() => info!("received shutdown signal, shutting down"),
        result = server.fuse() => {
            match result {
                Ok(Ok(())) => info!("gRPC server exited cleanly"),
                Ok(Err(e)) => warn!(error = %e, "gRPC server returned error"),
                Err(e) => warn!(error = %e, "gRPC server task join error"),
            }
        }
    }

    // ALWAYS persist the journal first so anything still buffered (last commit,
    // a Drop-time flush that the runtime cancel would otherwise skip) lands on
    // disk before we exit. fjall's Journal::Drop also calls persist(SyncAll),
    // but on the fdstore path we historically called `std::process::exit(0)`
    // to skip user destructors — which also skips fjall's Drop. The explicit
    // call here makes durability independent of whether Drop fires.
    if let Err(e) = shutdown_store.persist_now() {
        warn!(error = %e, "final fjall persist failed; in-flight snapshot metadata may be lost on next start");
    }

    // When systemd is preserving our descriptors, leave the kernel mounts up
    // and let Rust destructors run normally: nothing in the supervisor or
    // overlay engine drops the FUSE mounts (only `stop_instance()` does, and
    // that's called explicitly from `shutdown_all` / `preserve_for_failover`).
    // Returning Ok(()) here lets fjall's worker pool flush + drop cleanly,
    // which an earlier `std::process::exit(0)` skipped.
    if nydus_snapshotter::fdstore::is_available() {
        shutdown_supervisor.preserve_for_failover().await;
        info!("preserving armed nydus mounts for failover");
        return Ok(());
    }
    shutdown_supervisor.shutdown_all().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_profile_accepts_known_values_case_insensitively() {
        assert_eq!(parse_profile("auto").unwrap(), Profile::Auto);
        assert_eq!(parse_profile("k3s").unwrap(), Profile::K3s);
        assert_eq!(parse_profile("containerd").unwrap(), Profile::Containerd);
        // Case- and whitespace-insensitive, matching operator-typed env values.
        assert_eq!(parse_profile("  K3S ").unwrap(), Profile::K3s);
        assert_eq!(parse_profile("Containerd").unwrap(), Profile::Containerd);
    }

    #[test]
    fn parse_profile_rejects_unknown_values() {
        let err = parse_profile("kubernetes").unwrap_err();
        assert!(err.contains("invalid profile"));
        assert!(err.contains("auto, k3s, containerd"));
    }

    /// The `--profile` value_parser must accept exactly the same spellings the
    /// TOML `profile` field does (serde `rename_all = "lowercase"`), so an env
    /// override and a config file never disagree on what "k3s" means.
    #[test]
    fn parse_profile_matches_toml_deserialization() {
        for name in ["auto", "k3s", "containerd"] {
            let via_flag = parse_profile(name).unwrap();
            let via_toml: Profile = toml::from_str(&format!("profile = {name:?}"))
                .map(|w: ProfileWrap| w.profile)
                .unwrap();
            assert_eq!(via_flag, via_toml, "mismatch for {name}");
        }
    }

    #[derive(serde::Deserialize)]
    struct ProfileWrap {
        profile: Profile,
    }
}
