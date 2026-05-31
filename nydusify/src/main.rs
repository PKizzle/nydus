// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#![deny(warnings)]

fn main() {
    if let Err(err) = nydusify::run_from_args() {
        eprintln!("nydusify: {err:#}");
        std::process::exit(1);
    }
}
