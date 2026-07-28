// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! APIs for the Nydus Image Service
//!
//! The `nydus-api` crate defines API and related data structures for Nydus Image Service.
//! All data structures used by the API are encoded in JSON format.

#[cfg_attr(feature = "handler", macro_use)]
extern crate log;
#[macro_use]
extern crate serde;
pub mod config;
pub use config::*;
#[macro_use]
pub mod http;
pub use self::http::*;

#[cfg(feature = "handler")]
pub(crate) mod http_endpoint_common;
#[cfg(feature = "handler")]
pub(crate) mod http_endpoint_v1;
#[cfg(feature = "handler")]
pub(crate) mod http_endpoint_v2;
#[cfg(feature = "handler")]
pub(crate) mod http_handler;
#[cfg(feature = "handler")]
pub(crate) mod http_prometheus;

#[cfg(feature = "handler")]
pub use http_handler::{
    EndpointHandler, HTTP_ROUTES, HttpResult, HttpRoutes, extract_query_part, start_http_thread,
};

/// Application build and version information.
#[derive(Serialize, Clone)]
pub struct BuildTimeInfo {
    pub package_ver: String,
    pub git_commit: String,
    pub build_time: String,
    pub profile: String,
    pub rustc: String,
}
