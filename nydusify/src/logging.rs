// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::fs::{File, OpenOptions};
use std::io::{Result as IoResult, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

pub fn init(debug: bool, log_level: &str, log_file: Option<&Path>) -> Result<()> {
    let filter = if debug { "debug" } else { log_level };
    let filter = EnvFilter::try_new(filter)
        .with_context(|| format!("invalid log level or tracing filter `{filter}`"))?;

    if let Some(path) = log_file {
        let writer = LogFileWriter::open(path)?;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_writer(writer)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init();
    }

    Ok(())
}

struct LogFileWriter {
    file: Mutex<File>,
}

impl LogFileWriter {
    fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open log file {}", path.display()))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl<'writer> MakeWriter<'writer> for LogFileWriter {
    type Writer = LogFileGuard<'writer>;

    fn make_writer(&'writer self) -> Self::Writer {
        let guard = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        LogFileGuard { guard }
    }
}

struct LogFileGuard<'writer> {
    guard: MutexGuard<'writer, File>,
}

impl Write for LogFileGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.guard.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.guard.flush()
    }
}
