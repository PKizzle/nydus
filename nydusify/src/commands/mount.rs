// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::path::PathBuf;

use anyhow::Result;
use serde::Serialize;
use tracing::info;

use crate::cli::{BackendType, MountArgs};

use super::common::resolve_backend_config;
use super::pending_operation;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MountPlan {
    pub target: String,
    pub backend_type: String,
    pub mount_path: PathBuf,
    pub prefetch: bool,
    pub platform: String,
}

pub fn run(args: MountArgs) -> Result<()> {
    let plan = plan(&args)?;
    info!(target = %plan.target, mount_path = %plan.mount_path.display(), "validated nydusify-rs mount request");
    Err(pending_operation("mount"))
}

pub fn plan(args: &MountArgs) -> Result<MountPlan> {
    let _ = resolve_backend_config(
        args.backend_type,
        args.backend_config.as_deref(),
        args.backend_config_file.as_deref(),
        "",
    )?;
    let backend_type = args.backend_type.unwrap_or(BackendType::Registry).as_str();

    Ok(MountPlan {
        target: args.target.clone(),
        backend_type: backend_type.to_string(),
        mount_path: args.mount_path.clone(),
        prefetch: args.prefetch,
        platform: args.platform.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::{default_platform, BackendType};

    fn base_args() -> MountArgs {
        MountArgs {
            target: "registry.example.com/base:latest-nydus".to_string(),
            target_insecure: false,
            backend_type: None,
            backend_config: None,
            backend_config_file: None,
            prefetch: false,
            mount_path: PathBuf::from("./image-fs"),
            platform: default_platform(),
            work_dir: PathBuf::from("./tmp"),
            nydusd: PathBuf::from("nydusd"),
        }
    }

    #[test]
    fn defaults_to_registry_backend() {
        let mut args = base_args();
        args.prefetch = true;

        let plan = plan(&args).unwrap();

        assert_eq!(plan.target, "registry.example.com/base:latest-nydus");
        assert_eq!(plan.backend_type, "registry");
        assert!(plan.prefetch);
    }

    #[test]
    fn rejects_non_registry_backend_without_config() {
        let mut args = base_args();
        args.backend_type = Some(BackendType::Localfs);

        let err = plan(&args).unwrap_err();

        assert!(err.to_string().contains("--backend-config"));
    }
}
