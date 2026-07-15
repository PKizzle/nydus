// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! OCI Distribution client with both **pull** and **push** support.
//!
//! This crate is a self-contained OCI Distribution Spec client for the Nydus
//! tooling (primarily the `nydusify` CLI).
//!
//! # Runtime model
//!
//! The crate targets **CLI use on compio**: everything is async and runs on a
//! single-threaded compio runtime. The underlying [`cyper::Client`] is `!Send`
//! (Rc-based, bound to the compio current-thread runtime), so
//! [`RegistryClient`](client::RegistryClient) is `!Send` too and the public
//! API carries no `Send` bounds. Callers on a multi-threaded runtime must
//! confine the client to one thread; a plain `#[compio::main]` binary can use
//! it directly.
//!
//! # Auth flow
//!
//! Every request is first sent with the best credential at hand (a cached
//! bearer token for the request's scope, else HTTP basic auth if credentials
//! were provided or found in `~/.docker/config.json`). On a `401 Unauthorized`
//! the `WWW-Authenticate: Bearer` challenge from **that** response is parsed,
//! a token is fetched from the challenge's realm (with the challenge's scope
//! when present, else a scope built from the operation: `repository:<repo>:pull`
//! for reads, `repository:<repo>:pull,push` for uploads), cached, and the
//! request is retried exactly once. See [`auth`] for the building blocks.
//!
//! # Push protocol
//!
//! Blob push is the **monolithic** two-step upload from the distribution spec:
//! `POST /v2/<repo>/blobs/uploads/` to open a session, then a single `PUT` to
//! the returned `Location` with `?digest=sha256:...` appended (correctly,
//! whether the location already carries query parameters) and the whole blob
//! as the body. A `HEAD /v2/<repo>/blobs/<digest>` runs first so existing
//! blobs are deduplicated without an upload, and cross-repo mounting
//! (`POST ...?mount=<digest>&from=<repo>`) is available separately. Chunked
//! `PATCH` uploads are deliberately **out of scope** for now.

pub mod auth;
pub mod client;
pub mod reference;
pub mod types;

pub use client::{FetchedManifest, RegistryClient, RegistryClientOptions};
pub use reference::ImageReference;
pub use types::{
    Descriptor, History, ImageConfig, Index, Manifest, Platform, RootFs, sha256_digest,
    verify_digest,
};
