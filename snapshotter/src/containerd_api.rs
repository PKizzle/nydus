// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Generated containerd API (see `build.rs`), shared by every containerd client in the crate.
//!
//! Module nesting must match the protobuf package paths so the cross-package `super::…` refs
//! the prost generator emits (e.g. `Image.target: super::super::super::types::Descriptor`)
//! resolve.

pub mod types {
    tonic::include_proto!("containerd.types");

    pub mod transfer {
        tonic::include_proto!("containerd.types.transfer");
    }
}

pub mod services {
    pub mod content {
        pub mod v1 {
            tonic::include_proto!("containerd.services.content.v1");
        }
    }
    pub mod images {
        pub mod v1 {
            tonic::include_proto!("containerd.services.images.v1");
        }
    }
    pub mod streaming {
        pub mod v1 {
            tonic::include_proto!("containerd.services.streaming.v1");
        }
    }
    pub mod transfer {
        pub mod v1 {
            tonic::include_proto!("containerd.services.transfer.v1");
        }
    }
}
