// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Recover an OS errno from an error chain.
//!
//! Nydus has several boundaries where a rich Rust error has to collapse back into a single
//! integer: the fanotify pre-content handler answers a permission event with
//! `FAN_DENY_ERRNO(e)`, the FUSE server returns an errno to the kernel, the C API in `clib`
//! sets `errno`, and the NBD server maps to its own wire codes. Each of those needs the errno
//! that the *original* syscall produced, which by then may be several typed-error layers down.
//!
//! The rule the workspace follows is: **capture the errno once, at the syscall site, as a raw
//! `Os` [`std::io::Error`] stored in a `#[source]` field — never re-wrap it into a `Custom`
//! `io::Error`.** [`source_errno`] then walks back down to it.

/// Return the first OS errno found on `err`'s source chain, or `None` if there is none.
///
/// Walks `err` itself and then each `source()` in turn, so an errno survives being nested
/// inside any number of `thiserror` enums as long as each layer declares its cause with
/// `#[source]` (or `#[from]`, which implies it).
///
/// # The `io::Error` subtlety
///
/// [`std::io::Error`] does not behave like an ordinary error in a chain. For a `Custom` error
/// built by `io::Error::new(kind, payload)`, `source()` returns **`payload.source()`** — it
/// skips the payload itself. A plain `source()` walk therefore steps straight over a payload
/// that is itself an `Os` `io::Error` and loses the errno.
///
/// So every `io::Error` node is inspected explicitly instead: first `raw_os_error()`, and if
/// that is `None`, descend through `get_ref()` rather than `source()`.
pub fn source_errno(err: &(dyn std::error::Error + 'static)) -> Option<i32> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);

    while let Some(e) = cur {
        if let Some(ioe) = e.downcast_ref::<std::io::Error>() {
            if let Some(errno) = ioe.raw_os_error() {
                return Some(errno);
            }
            // `get_ref()`, not `source()`: see the note above.
            cur = ioe
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static));
            continue;
        }
        cur = e.source();
    }

    None
}

/// An [`std::io::Error`] payload that adds a message without hiding the cause.
#[derive(Debug, thiserror::Error)]
#[error("{context}")]
struct Contextual {
    context: String,
    #[source]
    source: std::io::Error,
}

/// Attach `context` to an OS error, keeping both its `ErrorKind` and its errno.
///
/// Use this where a function is pinned to `io::Result` by a std or external trait and so cannot
/// return a typed error, but the bare errno ("Invalid argument (os error 22)") would leave the
/// caller guessing which operation failed.
///
/// The result keeps `err`'s [`ErrorKind`](std::io::ErrorKind), reports `context` from `Display`,
/// and stores `err` as the payload's source — so [`source_errno`] still recovers the errno.
/// This is what the old thread-local errno macro only pretended to do: it passed the message
/// to `make_error`, which logged it under a non-default feature and returned the error unchanged.
pub fn with_context(err: std::io::Error, context: impl Into<String>) -> std::io::Error {
    std::io::Error::new(
        err.kind(),
        Contextual {
            context: context.into(),
            source: err,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Anonymous: brings `source()` into scope without colliding with `io::Error`.
    use std::error::Error as _;
    use std::io::{Error, ErrorKind};

    #[test]
    fn with_context_keeps_kind_message_and_errno() {
        let err = with_context(
            Error::from_raw_os_error(libc::ENOSPC),
            "failed to write the chunk map",
        );

        assert_eq!(err.kind(), Error::from_raw_os_error(libc::ENOSPC).kind());
        assert_eq!(err.to_string(), "failed to write the chunk map");
        // The whole point: the errno is still reachable, unlike a `format!`-ed message.
        assert_eq!(source_errno(&err), Some(libc::ENOSPC));
    }

    #[derive(Debug, thiserror::Error)]
    #[error("outer")]
    struct Outer(#[source] Inner);

    #[derive(Debug, thiserror::Error)]
    #[error("inner")]
    struct Inner(#[source] Error);

    #[derive(Debug, thiserror::Error)]
    #[error("no cause at all")]
    struct Bare;

    #[test]
    fn finds_a_direct_os_error() {
        let err = Error::from_raw_os_error(libc::ENOSPC);
        assert_eq!(source_errno(&err), Some(libc::ENOSPC));
    }

    #[test]
    fn finds_an_os_error_two_enums_deep() {
        // The shape every boundary in the workspace actually sees: a syscall failure captured
        // at the bottom and wrapped by each layer on the way up.
        let err = Outer(Inner(Error::from_raw_os_error(libc::EDQUOT)));
        assert_eq!(source_errno(&err), Some(libc::EDQUOT));
    }

    #[test]
    fn sees_through_a_custom_io_error_wrapping_an_os_one() {
        // The regression this function exists for. `io::Error::source()` returns the *payload's*
        // source, not the payload, so walking `source()` alone steps over the inner `Os` error
        // and reports `None`. Descending via `get_ref()` finds it.
        let custom = Error::other(Error::from_raw_os_error(libc::EIO));
        assert_eq!(custom.raw_os_error(), None, "precondition: outer is Custom");
        assert!(
            custom.source().is_none(),
            "precondition: source() skips the payload, which is what makes this case tricky"
        );
        assert_eq!(source_errno(&custom), Some(libc::EIO));
    }

    #[test]
    fn sees_through_a_custom_io_error_nested_in_an_enum() {
        let err = Outer(Inner(Error::other(Error::from_raw_os_error(libc::ENOENT))));
        assert_eq!(source_errno(&err), Some(libc::ENOENT));
    }

    #[test]
    fn reports_none_when_no_syscall_failed() {
        assert_eq!(source_errno(&Bare), None);

        // A `Custom` io::Error whose payload is a plain message carries no errno either --
        // this is exactly what the old EINVAL error macro produced.
        let msg = Error::new(ErrorKind::InvalidInput, "bad argument");
        assert_eq!(source_errno(&msg), None);

        assert_eq!(source_errno(&Outer(Inner(msg))), None);
    }

    #[test]
    fn returns_the_outermost_errno_when_several_are_present() {
        // Layers closer to the caller describe the failure the caller acted on, so the first
        // errno found wins rather than the deepest.
        let inner = Error::from_raw_os_error(libc::ENOENT);
        let outer = Error::other(Inner(inner));
        assert_eq!(source_errno(&outer), Some(libc::ENOENT));

        let err = Inner(Error::from_raw_os_error(libc::EACCES));
        assert_eq!(source_errno(&err), Some(libc::EACCES));
    }
}
