// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Process-wide panic policy.
//!
//! Release builds unwind, but only code that runs inside [`contain`] may survive a panic. Every
//! binary installs [`abort_on_uncontained_panic`] at startup, so a panic anywhere else aborts the
//! process exactly as `panic = "abort"` would. That keeps the old guarantee for code that relies
//! on process death (a poisoned lock or a half-updated structure is never used again) while a
//! containment boundary, such as one fanotify worker, can fail on its own and be restarted.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

thread_local! {
    static CONTAINED: Cell<bool> = const { Cell::new(false) };
}

/// Run `f`, catching a panic instead of aborting the process.
///
/// The caller owns the consequences: whatever state `f` touched must be treated as failed
/// (not used again for serving) when this returns `Err`.
pub fn contain<R>(f: impl FnOnce() -> R) -> std::thread::Result<R> {
    let outer = CONTAINED.with(|c| c.replace(true));
    let result = catch_unwind(AssertUnwindSafe(f));
    CONTAINED.with(|c| c.set(outer));
    result
}

/// Install a panic hook that runs the current hook (logging), then aborts unless the panicking
/// thread is inside [`contain`]. Call it after any other hook is installed.
pub fn abort_on_uncontained_panic() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        previous(info);
        if !CONTAINED.with(Cell::get) {
            std::process::abort();
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contain_catches_and_restores_the_flag() {
        assert!(contain(|| panic!("contained")).is_err());
        assert_eq!(contain(|| 7).unwrap(), 7);
        assert!(!CONTAINED.with(Cell::get));
        // Nested: the inner boundary must not clear the outer one.
        contain(|| {
            let _ = contain(|| ());
            assert!(CONTAINED.with(Cell::get));
        })
        .unwrap();
    }

    /// The hook aborts on a panic outside `contain` and lets one inside it unwind. Runs in a
    /// child process, because the abort would take the test harness down with it.
    #[test]
    fn hook_aborts_only_uncontained_panics() {
        const CHILD: &str = "NYDUS_PANIC_POLICY_CHILD";
        if let Ok(mode) = std::env::var(CHILD) {
            abort_on_uncontained_panic();
            assert!(contain(|| panic!("contained")).is_err());
            if mode == "uncontained" {
                let _ = std::thread::spawn(|| panic!("uncontained")).join();
            }
            return;
        }
        let run = |mode: &str| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "panic_policy::tests::hook_aborts_only_uncontained_panics",
                ])
                .args(["--nocapture", "--test-threads=1"])
                .env(CHILD, mode)
                .output()
                .unwrap()
                .status
        };
        assert!(run("contained").success());
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(run("uncontained").signal(), Some(libc::SIGABRT));
        }
    }
}
