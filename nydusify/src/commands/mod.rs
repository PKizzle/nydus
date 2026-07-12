// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

pub mod check;
pub mod common;
pub mod convert;
pub mod copy;
pub mod mount;

use anyhow::Result;

use crate::cli::Commands;

pub async fn execute(command: Commands) -> Result<()> {
    match command {
        Commands::Convert(args) => convert::run(*args).await,
        Commands::Check(args) => check::run(*args).await,
        Commands::Mount(args) => mount::run(*args).await,
        Commands::Copy(args) => copy::run(*args).await,
    }
}
