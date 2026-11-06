// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nix::sys::signal;

/// Register signal handler for a signal.
pub fn register_signal_handler(sig: signal::Signal, handler: extern "C" fn(libc::c_int)) {
    let sa = signal::SigAction::new(
        signal::SigHandler::Handler(handler),
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );

    // SAFETY: `handler` is an `extern "C" fn` supplied by the caller for use as a signal handler,
    // which must only perform async-signal-safe operations; installing it does not touch any Rust
    // state.
    unsafe {
        // Signal registration fails, just panic since nydusd won't work properly.
        signal::sigaction(sig, &sa).unwrap();
    }
}
