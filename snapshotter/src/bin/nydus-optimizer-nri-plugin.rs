// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Rust optimizer NRI plugin entrypoint.
//!
//! Two modes:
//!
//! 1. `--nri-listen-socket <path>` runs as a long-lived containerd NRI plugin.
//!    On `StartContainer` it POSTs to `/api/v1/access-tracer/start` so the
//!    snapshotter's in-process tracer resets `settle_max` to real container
//!    start (instead of snapshot `Prepare`). On `StopContainer` it POSTs to
//!    `/api/v1/access-tracer/settle` so a short-lived container ships its
//!    profile immediately rather than waiting up to `settle_max` for the
//!    timer.
//!
//! 2. Without `--nri-listen-socket` it acts as a one-shot CLI that converts
//!    container access records (collected by an external optimizer/fanotify
//!    sidecar) into a Nydus prefetch profile and submits it to the
//!    system-controller's `/api/v1/prefetch/profile` endpoint.

use anyhow::{Context, Result, bail};
use clap::Parser;
use nydus_snapshotter::nri::{AccessProfileRecord, DEFAULT_SYSCTL_SOCKET, SysctlClient};
use nydus_snapshotter::nri_ttrpc::{NriTtrpcConfig, serve_optimizer_plugin};
use nydus_snapshotter::prefetch_profile::PrefetchProfile;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "nydus-optimizer-nri-plugin",
    about = "Submit optimizer access profiles to the Nydus snapshotter"
)]
struct Args {
    /// Nydus sysctl Unix socket used by /api/v1/prefetch/profile and
    /// /api/v1/access-tracer/*.
    #[arg(long, default_value = DEFAULT_SYSCTL_SOCKET)]
    sysctl_socket: PathBuf,

    /// Image reference for newline path input.
    #[arg(long)]
    image: Option<String>,

    /// Read access records from this file instead of stdin.
    #[arg(long)]
    input: Option<PathBuf>,

    /// Listen on this Unix socket as a native NRI ttrpc Plugin service.
    /// When set, the binary runs as a long-lived plugin instead of a
    /// one-shot CLI.
    #[arg(long)]
    nri_listen_socket: Option<PathBuf>,

    /// Optional containerd NRI runtime socket to register with.
    #[arg(long)]
    nri_runtime_socket: Option<PathBuf>,

    /// NRI plugin name used during registration.
    #[arg(long, default_value = "nydus-optimizer")]
    name: String,

    /// NRI plugin invocation index used during registration.
    #[arg(long, default_value = "80")]
    idx: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(listen_socket) = args.nri_listen_socket.clone() {
        return serve_optimizer_plugin(NriTtrpcConfig {
            listen_socket,
            runtime_socket: args.nri_runtime_socket.clone(),
            sysctl_socket: args.sysctl_socket.clone(),
            plugin_name: args.name.clone(),
            plugin_idx: args.idx.clone(),
        });
    }
    let input = read_input(args.input.as_ref())?;
    let profile = profile_from_input(&input, args.image.as_deref())?;
    let response = SysctlClient::new(args.sysctl_socket).put_prefetch_profile(&profile)?;
    println!(
        "submitted optimizer profile for {} image(s): {}",
        response.images, profile.image
    );
    Ok(())
}

fn read_input(path: Option<&PathBuf>) -> Result<Vec<u8>> {
    let mut input = Vec::new();
    match path {
        Some(path) => {
            input = std::fs::read(path)
                .with_context(|| format!("failed to read input file {}", path.display()))?;
        }
        None => {
            std::io::stdin()
                .read_to_end(&mut input)
                .context("failed to read stdin")?;
        }
    }
    if input.is_empty() {
        bail!("empty optimizer profile input");
    }
    Ok(input)
}

fn profile_from_input(input: &[u8], image: Option<&str>) -> Result<PrefetchProfile> {
    if let Ok(profile) = serde_json::from_slice::<PrefetchProfile>(input) {
        return Ok(profile);
    }
    if let Ok(records) = serde_json::from_slice::<Vec<AccessProfileRecord>>(input) {
        let image = image
            .map(str::to_string)
            .or_else(|| records.first().map(|record| record.image.clone()))
            .context("access record input requires an image")?;
        return Ok(PrefetchProfile::from_access_records(image, records));
    }
    let image = image.context("newline path input requires --image")?;
    let records = String::from_utf8_lossy(input)
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(|path| AccessProfileRecord::new("optimizer", image, path, "open"))
        .collect::<Vec<_>>();
    if records.is_empty() {
        bail!("optimizer input did not contain any accessed paths");
    }
    Ok(PrefetchProfile::from_access_records(image, records))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_profile_from_access_records() {
        let input = br#"[
            {"container_id":"ctr","image":"registry.local/app:1","path":"/bin/app","op":"open","timestamp_unix":1},
            {"container_id":"ctr","image":"registry.local/app:1","path":"/bin/app","op":"open","timestamp_unix":2}
        ]"#;
        let profile = profile_from_input(input, None).unwrap();
        assert_eq!(profile.image, "registry.local/app:1");
        assert_eq!(profile.files.len(), 1);
        assert_eq!(profile.files[0].path, "/bin/app");
        assert_eq!(profile.files[0].hits, 2);
    }

    #[test]
    fn builds_profile_from_newline_paths() {
        let profile = profile_from_input(b"/bin/app\n/lib/libc.so\n", Some("image")).unwrap();
        assert_eq!(profile.image, "image");
        assert_eq!(profile.prefetch_files(), vec!["/bin/app", "/lib/libc.so"]);
    }
}
