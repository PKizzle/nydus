// SPDX-License-Identifier: Apache-2.0

//! One lazily created compio runtime per thread, for synchronous code that has to drive a
//! `!Send` future (cyper HTTP, prefetch workers) to completion.
//!
//! compio's `Runtime` is `!Send`, so it cannot be shared across threads; the compio HTTP
//! backends, the prefetch workers and the snapshotter's referrer and peer-mirror clients all use
//! this one per-thread instance, so a `blocking` pool thread holds at most one io_uring instance
//! however many of them it serves. Because it is shared, a future driven here must not itself
//! call [`block_on`]: offload such work with `blocking::unblock`. Idle `blocking` pool threads
//! exit, and their runtime with them.
//!
//! Creating a runtime can fail (`EMFILE`, io_uring setup limits). The failure is returned to the
//! caller with its errno intact and is not cached: the next call on the same thread retries.

use std::cell::OnceCell;
use std::future::Future;
use std::io;

use compio::runtime::Runtime;

/// The calling thread has no compio runtime and could not create one.
#[derive(Debug, thiserror::Error)]
#[error("failed to create compio runtime, {0}")]
pub struct RuntimeUnavailable(#[source] pub io::Error);

thread_local! {
    static RUNTIME: OnceCell<Runtime> = const { OnceCell::new() };
}

/// Run `fut` to completion on this thread's compio runtime, creating the runtime on first use.
///
/// Must not be called from inside a future already running on a compio runtime.
pub fn block_on<F: Future>(fut: F) -> Result<F::Output, RuntimeUnavailable> {
    block_on_with(Runtime::new, fut)
}

fn block_on_with<F: Future>(
    build: impl FnOnce() -> io::Result<Runtime>,
    fut: F,
) -> Result<F::Output, RuntimeUnavailable> {
    RUNTIME.with(|cell| {
        let rt = match cell.get() {
            Some(rt) => rt,
            None => {
                let rt = build().map_err(RuntimeUnavailable)?;
                cell.get_or_init(|| rt)
            }
        };
        Ok(rt.block_on(fut))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support io_uring")]
    fn creation_failure_keeps_errno_and_is_retried() {
        std::thread::spawn(|| {
            let err = block_on_with(|| Err(io::Error::from_raw_os_error(libc::EMFILE)), async {})
                .expect_err("injected builder failure must surface");
            assert_eq!(nydus_utils::source_errno(&err), Some(libc::EMFILE));

            // The failure is not cached: the next call on this thread builds a runtime.
            assert_eq!(block_on(async { 7 }).expect("runtime after retry"), 7);
            // ...and reuses it rather than calling the builder again.
            let reused = block_on_with(|| panic!("runtime must be reused"), async { 8 });
            assert_eq!(reused.expect("cached runtime"), 8);
        })
        .join()
        .unwrap();
    }
}
