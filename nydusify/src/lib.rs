// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#![deny(warnings)]

pub mod cli;
pub mod commands;
pub mod engine;
pub mod logging;

use anyhow::Result;
use clap::Parser;

pub use cli::{Cli, Commands};

pub fn run_from_args() -> Result<()> {
    run(Cli::parse())
}

pub fn run(cli: Cli) -> Result<()> {
    logging::init(cli.debug, cli.log_level.as_str(), cli.log_file.as_deref())?;
    commands::execute(cli.command)
}
