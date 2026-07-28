// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Remote blob access over a unix socket.
//!
//! **This module is disabled** -- `storage/src/lib.rs` has `//pub mod remote;` commented out
//! (since "storage: disable remote access related code"), so nothing here is compiled and
//! nothing here is tested.
//!
//! It predates the workspace's typed-error migration and never took part in it: its error
//! handling is still `io::Result` throughout. When the error macros were deleted, the calls
//! here were replaced with exactly what those macros expanded to -- a bare errno with the
//! message discarded -- because a behavioural change could not be verified in code that does
//! not build. Re-enabling this module therefore means porting its error handling first, not
//! just uncommenting the `mod` line.

pub use self::client::RemoteBlobMgr;
pub use self::server::Server;
mod client;
mod connection;
mod message;
mod server;
