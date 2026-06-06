// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Nydus containerd remote snapshotter (Rust rewrite).
//!
//! This crate implements a containerd proxy-plugin snapshotter that manages Nydus/RAFS
//! container image overlays. It links the `nydus-service` crate in-process so that
//! the snapshotter and nydusd functionality ship as a single binary.
//!
//! # Architecture
//!
//! ```text
//! containerd ──gRPC──▶ Snapshotter ──▶ Overlay Engine
//!                           │               │
//!                     Daemon Supervisor   RAFS metadata
//!                           │               │
//!                    ┌──────┴──────┐    BlobCacheMgr
//!                    │  nydus-service (linked)
//!                    │  ┌────────────────────────┐
//!                    │  │ fanotify │ fusedev │ blk │
//!                    │  └────────────────────────┘
//!                    └─────────────────────────────┘
//! ```
//!
//! The snapshotter prefers the **fanotify** pre-content backend (Linux ≥ 6.14) and
//! falls back to **fusedev** when the kernel lacks `FAN_CLASS_PRE_CONTENT` support.
//! The deprecated **fscache** backend has been removed entirely.
//!
//! See [`ARCHITECTURE.md`] in the repository root for the full design document.

#![deny(warnings)]
#![warn(clippy::all)]

pub mod access_tracer;
pub mod auto_zran;
pub mod cache;
pub mod config;
pub mod containerd_lookup;
pub mod content_store;
pub mod daemon;
pub mod failover;
pub mod fdstore;
pub mod grpc;
pub mod local_accel;
pub mod metrics;
pub mod nri;
pub mod nri_ttrpc;
pub mod overlay;
pub mod page_cache;
pub mod prefetch_profile;
pub mod probe;
pub mod recon;
pub mod source;
pub mod store;
pub mod sysctl;

/// Crate-local result type; all public APIs return `anyhow::Result`.
pub type Result<T> = anyhow::Result<T>;

/// Version information embedded at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
