// SPDX-License-Identifier: Apache-2.0

//! `nydus-image` writing to a reader that went away (`nydus-image check -v | head`).

use std::process::{Command, Stdio};

/// No abort and no success either: 141 (128 + SIGPIPE) is what a pipeline reports for a
/// writer killed by SIGPIPE, so `set -o pipefail` still notices the truncated output.
#[test]
fn closed_stdout_exits_like_sigpipe() {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    // Without a subcommand the binary prints its usage to stdout.
    let output = Command::new(env!("CARGO_BIN_EXE_nydus-image"))
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(141),
        "{:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
