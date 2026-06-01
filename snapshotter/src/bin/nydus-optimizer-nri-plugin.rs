// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Rust optimizer NRI plugin entrypoint.
//!
//! Converts container access records collected by an optimizer/fanotify sidecar
//! into a Nydus prefetch profile and submits it to the system-controller.

use anyhow::{Context, Result, bail};
use clap::Parser;
use nydus_snapshotter::nri::{AccessProfileRecord, DEFAULT_SYSCTL_SOCKET, SysctlClient};
use nydus_snapshotter::prefetch_profile::PrefetchProfile;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "nydus-optimizer-nri-plugin",
    about = "Submit optimizer access profiles to the Nydus snapshotter"
)]
struct Args {
    /// Nydus sysctl Unix socket used by /api/v1/prefetch/profile.
    #[arg(long, default_value = DEFAULT_SYSCTL_SOCKET)]
    sysctl_socket: PathBuf,

    /// Image reference for newline path input.
    #[arg(long)]
    image: Option<String>,

    /// Read access records from this file instead of stdin.
    #[arg(long)]
    input: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
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
