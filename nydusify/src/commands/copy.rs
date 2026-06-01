// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use anyhow::Result;
use serde::Serialize;
use tracing::info;

use crate::cli::CopyArgs;

use super::common::{resolve_backend_config, resolve_platform, validate_platform_selection};
use super::pending_operation;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CopyPlan {
    pub source: String,
    pub target: Option<String>,
    pub platform: String,
    pub all_platforms: bool,
    pub push_chunk_size: String,
}

pub fn run(args: CopyArgs) -> Result<()> {
    let plan = plan(&args)?;
    info!(source = %plan.source, target = ?plan.target, "validated nydusify-rs copy request");
    Err(pending_operation("copy"))
}

pub fn plan(args: &CopyArgs) -> Result<CopyPlan> {
    validate_platform_selection(args.all_platforms, args.platform.as_deref())?;
    let _ = resolve_backend_config(
        args.source_backend_type,
        args.source_backend_config.as_deref(),
        args.source_backend_config_file.as_deref(),
        "source-",
    )?;

    Ok(CopyPlan {
        source: args.source.clone(),
        target: args.target.clone(),
        platform: resolve_platform(args.platform.as_deref()),
        all_platforms: args.all_platforms,
        push_chunk_size: args.push_chunk_size.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::default_platform;

    fn base_args() -> CopyArgs {
        CopyArgs {
            source: "registry.example.com/base:latest".to_string(),
            target: Some("registry.example.com/base:copy".to_string()),
            source_insecure: false,
            target_insecure: false,
            source_backend_type: None,
            source_backend_config: None,
            source_backend_config_file: None,
            all_platforms: false,
            platform: None,
            push_chunk_size: "0MB".to_string(),
            work_dir: PathBuf::from("./tmp"),
            nydus_image: PathBuf::from("nydus-image"),
        }
    }

    #[test]
    fn builds_copy_plan_from_args() {
        let mut args = base_args();
        args.push_chunk_size = "64MB".to_string();

        let plan = plan(&args).unwrap();

        assert_eq!(plan.source, "registry.example.com/base:latest");
        assert_eq!(
            plan.target.as_deref(),
            Some("registry.example.com/base:copy")
        );
        assert_eq!(plan.push_chunk_size, "64MB");
    }

    #[test]
    fn rejects_all_platforms_with_custom_platform() {
        let mut args = base_args();
        args.all_platforms = true;
        args.platform = Some("linux/amd64".to_string());

        let err = plan(&args).unwrap_err();

        assert!(
            err.to_string()
                .contains("--all-platforms conflicts with --platform")
        );
    }

    #[test]
    fn resolves_default_platform_when_unset() {
        let plan = plan(&base_args()).unwrap();
        assert_eq!(plan.platform, default_platform());
    }
}
