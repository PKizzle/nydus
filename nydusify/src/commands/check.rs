// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use anyhow::Result;
use serde::Serialize;
use tracing::info;

use crate::cli::CheckArgs;

use super::common::resolve_backend_config;
use super::pending_operation;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CheckPlan {
    pub source: Option<String>,
    pub target: String,
    pub platform: String,
    pub multi_platform: bool,
}

pub fn run(args: CheckArgs) -> Result<()> {
    let plan = plan(&args)?;
    info!(target = %plan.target, platform = %plan.platform, "validated nydusify-rs check request");
    Err(pending_operation("check"))
}

pub fn plan(args: &CheckArgs) -> Result<CheckPlan> {
    let _ = resolve_backend_config(
        args.source_backend_type,
        args.source_backend_config.as_deref(),
        args.source_backend_config_file.as_deref(),
        "source-",
    )?;
    let _ = resolve_backend_config(
        args.target_backend_type,
        args.target_backend_config.as_deref(),
        args.target_backend_config_file.as_deref(),
        "target-",
    )?;

    Ok(CheckPlan {
        source: args.source.clone(),
        target: args.target.clone(),
        platform: args.platform.clone(),
        multi_platform: args.multi_platform,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::{BackendType, default_platform};

    fn base_args() -> CheckArgs {
        CheckArgs {
            source: Some("registry.example.com/base:latest".to_string()),
            target: "registry.example.com/base:latest-nydus".to_string(),
            source_insecure: false,
            target_insecure: false,
            source_backend_type: None,
            source_backend_config: None,
            source_backend_config_file: None,
            target_backend_type: None,
            target_backend_config: None,
            target_backend_config_file: None,
            multi_platform: false,
            platform: default_platform(),
            work_dir: PathBuf::from("./output"),
            nydus_image: PathBuf::from("nydus-image"),
            nydusd: PathBuf::from("nydusd"),
        }
    }

    #[test]
    fn builds_check_plan_from_args() {
        let mut args = base_args();
        args.multi_platform = true;

        let plan = plan(&args).unwrap();

        assert_eq!(
            plan.source.as_deref(),
            Some("registry.example.com/base:latest")
        );
        assert_eq!(plan.target, "registry.example.com/base:latest-nydus");
        assert!(plan.multi_platform);
    }

    #[test]
    fn rejects_target_backend_config_without_type() {
        let mut args = base_args();
        args.target_backend_config = Some("{}".to_string());

        let err = plan(&args).unwrap_err();

        assert!(
            err.to_string()
                .contains("--target-backend-type is required")
        );
    }

    #[test]
    fn accepts_registry_target_without_backend_config() {
        let mut args = base_args();
        args.target_backend_type = Some(BackendType::Registry);

        assert!(plan(&args).is_ok());
    }
}
