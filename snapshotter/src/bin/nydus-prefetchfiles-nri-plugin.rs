// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Rust prefetch-files NRI plugin entrypoint.
//!
//! The containerd NRI/ttrpc transport can feed this binary JSON event payloads
//! containing image annotations; the binary normalizes them and forwards the
//! resulting hints to the Nydus system-controller.

use anyhow::{Context, Result, bail};
use clap::Parser;
use nydus_snapshotter::nri::{
    DEFAULT_SYSCTL_SOCKET, PrefetchHint, SysctlClient, prefetch_hint_from_annotations,
};
use nydus_snapshotter::nri_ttrpc::{NriTtrpcConfig, serve_prefetch_plugin};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "nydus-prefetchfiles-nri-plugin",
    about = "Forward NRI prefetch annotations to the Nydus snapshotter"
)]
struct Args {
    /// Nydus sysctl Unix socket used by /api/v1/prefetch.
    #[arg(long, default_value = DEFAULT_SYSCTL_SOCKET)]
    sysctl_socket: PathBuf,

    /// Image reference for one-shot annotation injection.
    #[arg(long)]
    image: Option<String>,

    /// Newline-separated prefetch file list for one-shot injection.
    #[arg(long)]
    prefetch: Option<String>,

    /// Read JSON events from this file instead of stdin.
    #[arg(long)]
    input: Option<PathBuf>,

    /// Listen on this Unix socket as a native NRI ttrpc Plugin service.
    #[arg(long)]
    nri_listen_socket: Option<PathBuf>,

    /// Optional containerd NRI runtime socket to register with.
    #[arg(long)]
    nri_runtime_socket: Option<PathBuf>,

    /// NRI plugin name used during registration.
    #[arg(long, default_value = "nydus-prefetch")]
    name: String,

    /// NRI plugin invocation index used during registration.
    #[arg(long, default_value = "90")]
    idx: String,
}

#[derive(Debug, Deserialize)]
struct PrefetchEvent {
    image: String,
    #[serde(default)]
    annotations: HashMap<String, String>,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    prefetch: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(listen_socket) = args.nri_listen_socket.clone() {
        return serve_prefetch_plugin(NriTtrpcConfig {
            listen_socket,
            runtime_socket: args.nri_runtime_socket.clone(),
            sysctl_socket: args.sysctl_socket.clone(),
            plugin_name: args.name.clone(),
            plugin_idx: args.idx.clone(),
        });
    }
    let hints = collect_hints(&args)?;
    if hints.is_empty() {
        bail!("no Nydus prefetch hints found in input");
    }
    let response = SysctlClient::new(args.sysctl_socket).put_prefetch_hints(&hints)?;
    println!("injected prefetch hints for {} image(s)", response.images);
    Ok(())
}

fn collect_hints(args: &Args) -> Result<Vec<PrefetchHint>> {
    if let (Some(image), Some(prefetch)) = (args.image.as_ref(), args.prefetch.as_ref()) {
        return Ok(vec![PrefetchHint::from_newline_list(image, prefetch)]);
    }
    let input = read_input(args.input.as_ref())?;
    hints_from_json(&input)
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
        bail!("empty NRI prefetch input");
    }
    Ok(input)
}

fn hints_from_json(input: &[u8]) -> Result<Vec<PrefetchHint>> {
    if let Ok(hints) = serde_json::from_slice::<Vec<PrefetchHint>>(input) {
        return Ok(hints
            .into_iter()
            .filter(|hint| !hint.image.trim().is_empty() && !hint.files.is_empty())
            .collect());
    }
    if let Ok(events) = serde_json::from_slice::<Vec<PrefetchEvent>>(input) {
        return Ok(events.into_iter().filter_map(hint_from_event).collect());
    }
    let event = serde_json::from_slice::<PrefetchEvent>(input)
        .context("invalid prefetch event JSON; expected event object or array")?;
    Ok(hint_from_event(event).into_iter().collect())
}

fn hint_from_event(event: PrefetchEvent) -> Option<PrefetchHint> {
    if !event.files.is_empty() || !event.prefetch.trim().is_empty() {
        let mut files = PrefetchHint::from_newline_list(&event.image, &event.prefetch).files;
        files.extend(
            event
                .files
                .into_iter()
                .filter(|file| !file.trim().is_empty()),
        );
        return Some(PrefetchHint {
            image: event.image,
            files,
        });
    }
    prefetch_hint_from_annotations(event.image, &event.annotations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_snapshotter::nri::NYDUS_PREFETCH_ANNOTATION;

    #[test]
    fn parses_annotation_event() {
        let payload = format!(
            r#"{{"image":"registry.local/app:1","annotations":{{"{}":"/bin/app\n/lib/libc.so"}}}}"#,
            NYDUS_PREFETCH_ANNOTATION
        );
        let hints = hints_from_json(payload.as_bytes()).unwrap();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].files, vec!["/bin/app", "/lib/libc.so"]);
    }

    #[test]
    fn parses_direct_hint_array() {
        let hints =
            hints_from_json(br#"[{"image":"registry.local/app:1","files":["/bin/app"]}]"#).unwrap();
        assert_eq!(hints[0].files, vec!["/bin/app"]);
    }
}
