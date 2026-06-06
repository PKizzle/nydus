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

use nydus_snapshotter::config::SnapshotterConfig;
use nydus_snapshotter::daemon::DaemonSupervisor;

/// Command-line arguments for the snapshotter.
#[derive(Parser, Debug)]
#[command(
    name = "containerd-nydus",
    about = "Nydus containerd remote snapshotter"
)]
struct Args {
    /// Path to the unified TOML configuration file.
    #[arg(short, long)]
    config: Option<String>,

    /// Override the gRPC socket address.
    #[arg(short, long)]
    address: Option<String>,

    /// Override the root directory.
    #[arg(short, long)]
    root: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(short, long, default_value = "info")]
    log_level: String,
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

    // Probe filesystem drivers.
    let probe_results = nydus_snapshotter::probe::probe_drivers(&config.snapshotter.fs_drivers);
    for result in &probe_results {
        info!(
            driver = ?result.driver_type,
            available = result.available,
            reason = %result.reason,
            "driver probe result"
        );
    }

    // Select the best available driver.
    let selected = nydus_snapshotter::probe::select_driver(&probe_results);
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
