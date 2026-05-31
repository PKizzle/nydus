// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Nydus containerd remote snapshotter binary.
//!
//! Single binary that embeds the nydusd daemon in-process and serves
//! containerd's proxy-plugin gRPC protocol.

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
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

#[tokio::main]
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
    let server = tokio::spawn(async move {
        nydus_snapshotter::grpc::serve_with_supervisor(config, supervisor).await
    });

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM, shutting down"),
        _ = sigint.recv() => info!("received SIGINT, shutting down"),
        result = server => {
            match result {
                Ok(Ok(())) => info!("gRPC server exited cleanly"),
                Ok(Err(e)) => warn!(error = %e, "gRPC server returned error"),
                Err(e) => warn!(error = %e, "gRPC server task panicked"),
            }
        }
    }

    shutdown_supervisor.shutdown_all().await;
    Ok(())
}
