// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Local helpers shared by the commands that drive `nydus-image`.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use tracing::debug;

/// Run `nydus-image <args>`; on failure the error carries its stderr. `what`
/// completes "failed to ..." in that error.
pub fn run_nydus_image(nydus_image: &Path, args: &[OsString], what: &str) -> Result<()> {
    debug!(binary = %nydus_image.display(), ?args, what, "running nydus-image");
    let output = Command::new(nydus_image)
        .args(args)
        .output()
        .with_context(|| format!("spawn `{}` to {what}", nydus_image.display()))?;
    if !output.status.success() {
        bail!(
            "nydus-image failed to {what} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(())
}

/// (Re)create `dir` empty, so each `nydus-image` invocation owns a private dir
/// and "exactly one output file" is a structural guarantee.
pub fn fresh_dir(dir: &Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("clear directory {}", dir.display())),
    }
    std::fs::create_dir_all(dir).with_context(|| format!("create directory {}", dir.display()))
}

pub fn file_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len())
}
