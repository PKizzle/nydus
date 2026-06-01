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
    let shutdown_supervisor = supervisor.clone();
    let server = compio::runtime::spawn(async move {
        nydus_snapshotter::grpc::serve_with_supervisor(config, supervisor).await
    });

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

    shutdown_supervisor.shutdown_all().await;
    Ok(())
}
