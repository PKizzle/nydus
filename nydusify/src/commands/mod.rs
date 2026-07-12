// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

pub mod check;
pub mod common;
pub mod convert;
pub mod copy;
pub mod mount;

use anyhow::{Result, anyhow};

use crate::cli::Commands;

pub async fn execute(command: Commands) -> Result<()> {
    match command {
        Commands::Convert(args) => convert::run(*args).await,
        Commands::Check(args) => check::run(*args).await,
        Commands::Mount(args) => mount::run(*args).await,
        Commands::Copy(args) => copy::run(*args).await,
    }
}

pub(crate) fn pending_operation(name: &str) -> anyhow::Error {
    anyhow!(
        "{name} is validated by nydusify-rs but execution is not wired yet; next step is porting the containerd-converter based engine without acceleration-service dependencies"
    )
}
