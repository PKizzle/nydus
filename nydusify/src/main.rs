// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#![deny(warnings)]

#[compio::main]
async fn main() {
    // Release builds unwind for the daemons' sake; this CLI keeps abort semantics, so a panic
    // in any task ends the run instead of being swallowed by the async runtime.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        previous(info);
        std::process::abort();
    }));
    if let Err(err) = nydusify::run_from_args().await {
        eprintln!("nydusify: {err:#}");
        std::process::exit(1);
    }
}
